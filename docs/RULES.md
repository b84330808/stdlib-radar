# Rules

Every rule cites the section of What's New it comes from. `scripts/verify_docs.py` checks each citation against docs.python.org (weekly in CI), and `tests/test_runtime.py` checks each removal against the running interpreter on Python 3.9 to 3.15. List them from the command line with `stdlib-radar --list-rules`.

Not removed, despite earlier deprecation notices: `locale.getdefaultlocale()` was undeprecated in 3.15 ([What's New in 3.15, locale](https://docs.python.org/3.15/whatsnew/3.15.html#locale)), so it is not a rule.

**Python 3.13**

| API | Change | Detected as |
|---|---|---|
| [`aifc`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`audioop`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`chunk`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`cgi`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`cgitb`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`crypt`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`imghdr`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`mailcap`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`msilib`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`nis`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`nntplib`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`ossaudiodev`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`pipes`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`sndhdr`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`spwd`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`sunau`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`telnetlib`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`uu`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`xdrlib`](https://docs.python.org/3.13/whatsnew/3.13.html#pep-594-remove-dead-batteries-from-the-standard-library) | removed | import |
| [`lib2to3`](https://docs.python.org/3.13/whatsnew/3.13.html#to3) | removed | import |
| [`@classmethod over @property`](https://docs.python.org/3.13/whatsnew/3.13.html#builtins) | changed | pattern check |
| [`frame.clear() on a suspended frame`](https://docs.python.org/3.13/whatsnew/3.13.html#builtins) | changed | not detected |
| [`configparser.LegacyInterpolation`](https://docs.python.org/3.13/whatsnew/3.13.html#id3) | removed | name use |
| [`importlib.metadata.EntryPoint[...]`](https://docs.python.org/3.13/whatsnew/3.13.html#importlib-metadata) | removed | not detected |
| [`locale.resetlocale()`](https://docs.python.org/3.13/whatsnew/3.13.html#locale) | removed | name use |
| [`opcode.is_pseudo / MIN_PSEUDO_OPCODE / MAX_PSEUDO_OPCODE / ENABLE_SPECIALIZATION`](https://docs.python.org/3.13/whatsnew/3.13.html#opcode) | removed | name use |
| [`with pathlib.Path(...)`](https://docs.python.org/3.13/whatsnew/3.13.html#id4) | removed | pattern check |
| [`re.template() / re.TEMPLATE / re.T`](https://docs.python.org/3.13/whatsnew/3.13.html#id5) | removed | name use |
| [`tkinter.tix`](https://docs.python.org/3.13/whatsnew/3.13.html#tkinter-tix) | removed | import |
| [`RawTurtle.settiltangle()`](https://docs.python.org/3.13/whatsnew/3.13.html#turtle) | removed | method call (heuristic) |
| [`typing.io / typing.re`](https://docs.python.org/3.13/whatsnew/3.13.html#id6) | removed | import |
| [`TypedDict("TD", x=int)`](https://docs.python.org/3.13/whatsnew/3.13.html#id6) | removed | call arguments |
| [`unittest.makeSuite / findTestCases / getTestCaseNames`](https://docs.python.org/3.13/whatsnew/3.13.html#unittest) | removed | name use |
| [`TestProgram.usageExit()`](https://docs.python.org/3.13/whatsnew/3.13.html#unittest) | removed | method call (heuristic) |
| [`urlopen(cafile=/capath=/cadefault=)`](https://docs.python.org/3.13/whatsnew/3.13.html#urllib) | removed | call arguments |
| [`webbrowser.MacOSX`](https://docs.python.org/3.13/whatsnew/3.13.html#webbrowser) | removed | name use |
| [`getpass.getuser()`](https://docs.python.org/3.13/whatsnew/3.13.html#changes-in-the-python-api) | changed | pattern check |
| [`Path.glob("**")`](https://docs.python.org/3.13/whatsnew/3.13.html#changes-in-the-python-api) | changed | pattern check |

**Python 3.14**

| API | Change | Detected as |
|---|---|---|
| [`BooleanOptionalAction(type=/choices=/metavar=)`](https://docs.python.org/3.14/whatsnew/3.14.html#id8) | removed | pattern check |
| [`group.add_argument_group()`](https://docs.python.org/3.14/whatsnew/3.14.html#id8) | removed | pattern check |
| [`ast.Num / Str / Bytes / NameConstant / Ellipsis`](https://docs.python.org/3.14/whatsnew/3.14.html#id9) | removed | name use |
| [`NodeVisitor.visit_Num() etc.`](https://docs.python.org/3.14/whatsnew/3.14.html#id9) | changed | pattern check |
| [`ast.Constant.n / .s`](https://docs.python.org/3.14/whatsnew/3.14.html#id9) | removed | not detected |
| [`asyncio child watchers`](https://docs.python.org/3.14/whatsnew/3.14.html#id10) | removed | name use |
| [`AbstractEventLoopPolicy.get_child_watcher()`](https://docs.python.org/3.14/whatsnew/3.14.html#id10) | removed | method call (heuristic) |
| [`asyncio.get_event_loop()`](https://docs.python.org/3.14/whatsnew/3.14.html#id10) | changed | pattern check |
| [`email.utils.localtime(isdst=)`](https://docs.python.org/3.14/whatsnew/3.14.html#email) | removed | call arguments |
| [`importlib.abc.ResourceReader / Traversable / TraversableResources`](https://docs.python.org/3.14/whatsnew/3.14.html#importlib-abc) | removed | name use |
| [`copy/pickle of itertools iterators`](https://docs.python.org/3.14/whatsnew/3.14.html#itertools) | removed | not detected |
| [`pathlib.Path(..., **kwargs)`](https://docs.python.org/3.14/whatsnew/3.14.html#id11) | removed | call arguments |
| [`PurePath.relative_to(a, b)`](https://docs.python.org/3.14/whatsnew/3.14.html#id11) | removed | method call (heuristic) |
| [`pkgutil.get_loader() / find_loader()`](https://docs.python.org/3.14/whatsnew/3.14.html#pkgutil) | removed | name use |
| [`pty.master_open() / slave_open()`](https://docs.python.org/3.14/whatsnew/3.14.html#pty) | removed | name use |
| [`sqlite3.version / version_info`](https://docs.python.org/3.14/whatsnew/3.14.html#sqlite3) | removed | name use |
| [`named placeholders with a sequence`](https://docs.python.org/3.14/whatsnew/3.14.html#sqlite3) | removed | not detected |
| [`urllib.parse.Quoter`](https://docs.python.org/3.14/whatsnew/3.14.html#id12) | removed | name use |
| [`urllib.request.URLopener / FancyURLopener`](https://docs.python.org/3.14/whatsnew/3.14.html#id12) | removed | name use |
| [`functools.partial as a class attribute`](https://docs.python.org/3.14/whatsnew/3.14.html#changes-in-the-python-api) | changed | pattern check |
| [`gc.collect(1)`](https://docs.python.org/3.14/whatsnew/3.14.html#changes-in-the-python-api) | changed | pattern check |
| [`multiprocessing default start method`](https://docs.python.org/3.14/whatsnew/3.14.html#changes-in-the-python-api) | changed | not detected |

**Python 3.15**

| API | Change | Detected as |
|---|---|---|
| [`ast node constructors`](https://docs.python.org/3.15/whatsnew/3.15.html#id1) | changed | not detected |
| [`ctypes.SetPointerType()`](https://docs.python.org/3.15/whatsnew/3.15.html#id2) | removed | name use |
| [`strptime(s, "...%d...") without a year`](https://docs.python.org/3.15/whatsnew/3.15.html#datetime) | removed | pattern check |
| [`glob.glob0() / glob.glob1()`](https://docs.python.org/3.15/whatsnew/3.15.html#glob) | removed | name use |
| [`http.server.CGIHTTPRequestHandler`](https://docs.python.org/3.15/whatsnew/3.15.html#id3) | removed | name use |
| [`Loader.load_module()`](https://docs.python.org/3.15/whatsnew/3.15.html#importlib) | removed | method call (heuristic) |
| [`custom loader with only load_module()`](https://docs.python.org/3.15/whatsnew/3.15.html#importlib) | removed | pattern check |
| [`zipimport.zipimporter.load_module()`](https://docs.python.org/3.15/whatsnew/3.15.html#zipimport) | removed | not detected |
| [`importlib.resources.files(package=)`](https://docs.python.org/3.15/whatsnew/3.15.html#importlib-resources) | removed | call arguments |
| [`PurePath.is_reserved()`](https://docs.python.org/3.15/whatsnew/3.15.html#id4) | removed | method call (heuristic) |
| [`platform.java_ver()`](https://docs.python.org/3.15/whatsnew/3.15.html#platform) | removed | name use |
| [`sre_compile / sre_constants / sre_parse`](https://docs.python.org/3.15/whatsnew/3.15.html#sre) | removed | import |
| [`sysconfig.is_python_build(check_home)`](https://docs.python.org/3.15/whatsnew/3.15.html#sysconfig) | removed | call arguments |
| [`threading.RLock(...)`](https://docs.python.org/3.15/whatsnew/3.15.html#id5) | removed | call arguments |
| [`codeobject.co_lnotab`](https://docs.python.org/3.15/whatsnew/3.15.html#id6) | removed | method call (heuristic) |
| [`NamedTuple("P", x=int)`](https://docs.python.org/3.15/whatsnew/3.15.html#id7) | removed | call arguments |
| [`TypedDict("TD") / TypedDict("TD", None)`](https://docs.python.org/3.15/whatsnew/3.15.html#id7) | removed | pattern check |
| [`typing.no_type_check_decorator`](https://docs.python.org/3.15/whatsnew/3.15.html#id7) | removed | name use |
| [`Wave_read/Wave_write getmark()/setmark()/getmarkers()`](https://docs.python.org/3.15/whatsnew/3.15.html#id8) | removed | method call (heuristic) |
| [`text I/O without encoding=`](https://docs.python.org/3.15/whatsnew/3.15.html#whatsnew315-utf8-default) | encoding | pattern check, opt-in `--encoding` |
| [`importlib.metadata.metadata()`](https://docs.python.org/3.15/whatsnew/3.15.html#importlib-metadata) | changed | pattern check |
| [`sqlite3.connect(db, timeout, ...)`](https://docs.python.org/3.15/whatsnew/3.15.html#porting-to-python-3-15) | removed | call arguments |
| [`add_argument("-f", "-foo")`](https://docs.python.org/3.15/whatsnew/3.15.html#porting-to-python-3-15) | changed | pattern check |
