# 获取参数的规则

## 概述

这些获取参数的规则借鉴了一些支持引用和解引用、指针运算的编程语言的概念。

让我们描述一下这些规则，这里有一个例子：

```bash
main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)
```

这个规则可以简要概述如下：

```
functionName(argument1=(expr1):type1, argument2=(expr2):type2, argument3=(expr3):type3)
```

- argument1~3: 这是我们为要捕获的参数自定义的一个标识符名
- expr1~3: 这是参数值实际存储的有效地址，必须先从有效地址处读取数据，然后才能解析成期望类型
- type1~3: 这是参数值对应的数据类型，'s|u<bitwidth>' for 整数, 'c<bitwidth>' for 字符串
    - s64 表示64位 有符号整数
    - u64 表示64位 无符号整数
    - c64 表示共8字节的字符串

这里的 'expr' 部分是参数值实际存储的有效地址（EA, Effective Address)，联想下《计算机组成原理》会容易理解些。
下面来解释下这里的规则。

## 解释规则

### s.age rule: (+16(%ax)):s64

1. (%ax): `func (s *Student).String()`, `*Student` 是接收器，它将作为函数 `String()` 的第一个参数传递，而第一个参数将通过寄存器 [E|R]AX 传递，我们使用 '%ax' 表示物理寄存器 [E|R]AX。寄存器 AX 中存储的数据是对象 `Student{}` 的起始地址。
2. +16(%ax)，`Student.age` 成员的偏移量为16字节，您可以手动计算或运行脚本获取：
    ```bash
    $ ../scripts/offsets.py --bin ./main --expr 'main.Student'

    struct main.Student {
        struct string              name;                 /* 0    16 */
        int                        age;                  /* 16    8 */

        /* size: 24, cachelines: 1, members: 2 */
        /* last cacheline: 24 bytes */
    };
    ```

3. 好的，`EA=+16(%ax)`，`+16(%ax)` 外面的 `()` 只是为了可读性，所以我们得到最终的 `EA=(+16(%ax))`。
4. go-ftrace 将读取存储在有效地址处的数据，将读取多少字节？如何解码数据？这里使用了类型 `s64`，我们知道它是一个64位有符号整数。
5. 最后，我们得到了 `main.Student.age`，并将其显示为 `s.age=100`。

### s.name rule: (*+0(%ax)):c64

1. `(%ax)` 存储了对象 `Student{}` 的起始地址
2. 如果我们想要获取 `Student.name` 字符串，我们必须知道字符串的内存布局是如何排列的。也许你知道 `stringHeader`，如果是这样的话，那就更容易理解了。好的，我们可以通过运行 offsets.py 来获取布局：

    ```bash
    $ ../scripts/offsets.py --bin ./main --expr 'main.Student'

    struct main.Student {
            struct string              name;                 /*0    16 */
            int                        age;                  /*    16     8*/

            /* size: 24, cachelines: 1, members: 2 */
            /* last cacheline: 24 bytes */
    };
    ```

    首先，我们知道成员`name`的偏移量为0，但它的类型是一个`struct`，所以您必须检查`struct string`的布局以获取更多细节。

    ```bash
    $ ../scripts/offsets.py --bin ./main --expr 'main.Student->name'

    Member(name='name', type='string', is_pointer=False, offset=0)
    struct string {
            uint8 *str;                  /*     0     8 */
            int                        len;                  /*     8     8 */

            /* size: 16, cachelines: 1, members: 2 */
            /* last cacheline: 16 bytes */
    };
    ```

    然后，我们知道`struct string`包含一个指向字符数组的指针和一个长度字段。（这个`struct string`就是`stringHeader`）

    >注意：所以我们必须获取这两个字段才能得到准确的字符串数据，因此我们添加了另一个参数提取规则`s.name.len=(+8(%ax)):s64`。

3. `0+(%ax)` 和 `(%ax)` 的效果相同，`0+` 强调了计算 `name` 的成员偏移量，对于 `name.str` 来说也是一样的。
4. `name.str` 仍然是一个指针变量，它包含了实际字符串数据的地址，所以我们需要解引用这个指针来获取数据，这样我们就得到了 `*0+(%ax)`。这里的 `*` 表示解引用地址。
5. 现在我们得到了 `EA=(*0+(%ax))`，然后我们读取那里的数据，并将其解码为 `c64`，即一个8字节的字符串。
6. 所以你看到 `s.name=zhang<ni`，但是 `<ni` 应该被去掉，所以我们有了 `s.name.len=5` 来确定长度。

## 改进

- [ ] 通过脚本自动生成参数获取规则
