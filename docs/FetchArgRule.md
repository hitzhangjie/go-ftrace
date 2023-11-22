# Rules to Fetch Arguments

## Overview

This fetching arguments rules borrowing some concepts of programming 
languages that supports reference and dereference, pointer arithmetic.

Let's describe these rules, here is an example:

```bash
main.(*Student).String(s.name=(*+0(%ax)):c64, s.name.len=(+8(%ax)):s64, s.age=(+16(%ax)):s64)
```

The rule is summarized as following:

```
functionName(argument1=(expr1):type1, argument2=(expr2):type2, argument3=(expr3):type3)
```

- argument1~3: it's the identifier when displaying the value
- expr1~3: it's the EA where data stored, dereference must be done before decoded
- type1~3: it's the datatype, 's|u<bitwidth>' for integers, 'c<bitwidth>' for string
    - s64 for 64-bit signed integer 
    - u64 for 64-bit unsigned integer
    - c64 for 8-byte string

The 'expr' part is the EA (effective address) where data stored, let's explain the rule used.

## Explain the rules

### s.age rule: (+16(%ax)):s64

1. (%ax): `func (s *Student).String()`, `*Student` is the receiver, it will be passed as the 1st argument of function `String()`, and 1st argument will be passed via register [E|R]AX, we use '%ax' to represent the physical register [E|R]AX. The data stored in register AX is the starting address of object `Student{}`.
2. +16(%ax), offset of member `Student.age` is 16 bytes, you can calculate mannually or run the scripts to get it:
    ```bash
    $ ../scripts/offsets.py --bin ./main --expr 'main.Student'

    struct main.Student {
        struct string              name;                 /*0    16 */
        int                        age;                  /*    16     8*/

        /* size: 24, cachelines: 1, members: 2 */
        /* last cacheline: 24 bytes */
    };
    ```

3. well, the `EA=+16(%ax)`, the outer `()` of `+16(%ax)` is just for readability, so we get the final `EA=(+16(%ax))`.
4. go-ftrace will read the data stored at the effective address, how many bytes will be read? how to decoded the data? The type `s64` comes in, we know it's a 64-bit signed integer.
5. finally, we got the `main.Student.age`, and we display it as `s.age=100`.

### s.name rule: (*+0(%ax)):c64

1. `(%ax)` stores the starting address of the object `Student{}`
2. if we want to get the string of `Student.name string`, we must know how the memory layout of string is arranged. Maybe you know `stringHeader`, if so, that's easiser to understand. OK, we can get the layout by running offsets.py:

    ```bash
    $ ../scripts/offsets.py --bin ./main --expr 'main.Student'

    struct main.Student {
            struct string              name;                 /*0    16 */
            int                        age;                  /*    16     8*/

            /* size: 24, cachelines: 1, members: 2 */
            /* last cacheline: 24 bytes */
    };
    ```
    firstly, we know the offset of member `name` is 0, but its type is a `struct`, so you must inspect the layout of `struct string` to get more details.

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

    then, we know the `struct string` contains a pointer to the char array, and a length field. (this `struct string` is the `stringHeader`)

    >ps: so we must get the two fields to get the exact string data, so we add another argument fetching rule `s.name.len=(+8(%ax)):s64`.

3. `0+(%ax)` works the same as `(%ax)`, `0+` emphasizes the addressing by calculating the member offset for `name`, for `name.str`. 
4. `name.str` is still a pointer variable which contains address to the actual string data, so deference this pointer to get the data, then we get `*0+(%ax)`. Here `*` means deference the address.
5. now we get the `EA=(*0+(%ax))`, then we read the data there and decode it as `c64`, which is a 8-byte string.
6. so you see `s.name=zhang<ni`, but `<ni` should be dropped, so we have `s.name.len=5` to determine the length here.

## Improvements

- [ ] data in register %ax, %bx, ... aren't always pointers, may be `immediate operand`  
    example: `func(context.Context, f1 string, f2 int)`, f2 will passed as an immediate operand in register (go1.17 uses register to pass arguments)
- [ ] automatically generate the argument's fetching rule via scripts
