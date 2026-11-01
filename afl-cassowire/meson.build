project('afl-cassowire', 'cpp',
    version : '0.1.0',
    default_options : [
        'cpp_std=c++20',
        'warning_level=3',
        'werror=false',
        # The default `afl-cassowire` binary is optimized (-O3, no symbols). The
        # `afl-cassowire-dbg` target below overrides this with -O0 -g.
        'buildtype=release',
        # NDEBUG-only; the code has no assert()s. Keeping it off lets the dbg
        # target stay assert-enabled without fighting the buildtype flags.
        'b_ndebug=false',
    ])

# Check the compiler
compiler = meson.get_compiler('cpp')
code = '''
#ifndef __AFL_LOOP
#error "AFL++ persistent mode macros __AFL_LOOP not found. Compile with afl-clang-fast/afl-clang-lto."
#endif
#ifndef __AFL_INIT
#error "AFL++ persistent mode macros __AFL_INIT not found. Compile with afl-clang-fast/afl-clang-lto."
#endif

int main() { return 0; }
'''
result = compiler.run(code, name : 'check that is afl++ compiler', required: true)

# Dependencies
# No explicit dependency('threads'): the proxy has no threads and spdlog's
# pkg-config entry already propagates -pthread.
static_link = get_option('static_link')
yaml_cpp_dep = dependency('yaml-cpp', required : true, static : static_link)
argparse_dep = dependency('argparse', required : true, static : static_link)
# spdlog resolves fmt from inside its own subproject, which does not inherit
# the static kwarg from the spdlog dependency. Configure fmt first so that a
# fully static link uses libfmt.a instead of libfmt.so.
if static_link
    fmt_dep = dependency('fmt', required : false, static : true,
                         fallback : ['fmt', 'fmt_dep'])
endif
spdlog_dep = dependency('spdlog', required : true, static : static_link)

# network.cpp uses ppoll() for the microsecond response windows of sequence
# mode (recv_window); ppoll is exposed by glibc only with _GNU_SOURCE.
add_project_arguments('-D_GNU_SOURCE', language : 'cpp')

# Compile-time floor for the PROXY_LOG_TRACE/PROXY_LOG_DEBUG macros (src/log.hpp)
# is set per target: the optimized default binary compiles trace/debug out
# (INFO floor), while `afl-cassowire-dbg` keeps them (TRACE).


# ---------------------------
include_dirs = include_directories('src')

sources = files(
    'src/main.cpp',
    'src/args.cpp',
    'src/config.cpp',
    'src/coverage.cpp',
    'src/log.cpp',
    'src/process.cpp',
    'src/network.cpp',
    'src/utils.cpp',
)

link_args = []
if static_link
    link_args += '-static'
endif

# Optimized default build (-O3, no symbols): trace/debug log statements are
# compiled out so their (potentially expensive) arguments are never evaluated
# in the hot loop. AFL++'s compiler driver always injects -g, so strip the
# final binary explicitly; afl-cassowire-dbg keeps its symbols.
executable(
    'afl-cassowire',
    sources,
    include_directories : include_dirs,
    dependencies : [yaml_cpp_dep, argparse_dep, spdlog_dep],
    cpp_args : ['-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO'],
    link_args : link_args + ['-s'],
    install : true,
)

# Debug companion: unoptimized, with symbols, and trace/debug logging enabled.
# Builds alongside the default binary; use it for triage, not for fuzzing.
# The explicit -O0 wins over the release buildtype's -O3 (later flag wins).
executable(
    'afl-cassowire-dbg',
    sources,
    include_directories : include_dirs,
    dependencies : [yaml_cpp_dep, argparse_dep, spdlog_dep],
    cpp_args : ['-O0', '-g', '-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_TRACE'],
    link_args : link_args,
    install : true,
)
