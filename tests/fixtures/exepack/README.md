# EXEPACK fixtures

These files come from David Fifield's `exepack` test corpus:

- Source: <https://github.com/viiri/exepack>
- Revision: `a42f2c8fb1018feeb2c32fc7f7b1f01240d824c4`
- License: CC0 1.0 / public-domain dedication

`hello.exe` is the expected unpacked program. The six other files encode it using historical
Microsoft EXEPACK and LINK versions. They are retained to prove that the frontend decoder handles
multiple real stubs rather than one synthetic byte pattern.
