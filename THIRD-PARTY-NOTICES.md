# Third-party notices

The exe built by `build.ps1` bundles the components below and the compiled location
database, which draws on KapeFiles and ForensicArtifacts.

## Bundled in the exe

| Component | License | Source |
|---|---|---|
| Python runtime | PSF License 2.0 | https://www.python.org/ |
| pytsk3 | Apache-2.0 | https://github.com/py4n6/pytsk |
| The Sleuth Kit (inside pytsk3) | see https://sleuthkit.org/sleuthkit/licenses.php | https://github.com/sleuthkit/sleuthkit |
| libewf-python (libewf) | LGPL-3.0-or-later | https://github.com/libyal/libewf |
| libvhdi-python (libvhdi) | LGPL-3.0-or-later | https://github.com/libyal/libvhdi |
| libvmdk-python (libvmdk) | LGPL-3.0-or-later | https://github.com/libyal/libvmdk |
| libevtx-python (libevtx) | LGPL-3.0-or-later | https://github.com/libyal/libevtx |
| libregf-python (libregf) | LGPL-3.0-or-later | https://github.com/libyal/libregf |
| pyzipper | MIT | https://github.com/danifus/pyzipper |
| pycryptodomex | BSD-2-Clause and public domain | https://github.com/Legrandin/pycryptodome |
| olefile | BSD-2-Clause | https://github.com/decalage2/olefile |
| PyInstaller bootloader | GPL-2.0-or-later with the PyInstaller bootloader exception, which allows bundling programs under any license | https://pyinstaller.org/ |

The LGPL libraries are used unmodified. Their source is available at the links above; the
exe can be rebuilt against other versions of them with `build.ps1` from this repository.

## Data

ForensicArtifacts (https://github.com/ForensicArtifacts/artifacts), Apache License 2.0
(https://www.apache.org/licenses/LICENSE-2.0): Windows file locations of the antivirus
artifact definitions, with variables expanded to paths.

KapeFiles `Targets/Antivirus`:

```
MIT License

Copyright (c) 2023 Eric Zimmerman

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
