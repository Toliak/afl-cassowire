project('afl-cassowire', 'cpp',
    version : '0.1.0',
    default_options : [
        'cpp_std=c++20',
        'warning_level=3',
        'werror=false',
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

# Compile-time floor for the PROXY_LOG_TRACE/PROXY_LOG_DEBUG macros (src/log.hpp).
# With strip_low_logs=true the trace/debug statements compile to no-ops and the
# --log-level runtime flag can only go down to info.
if get_option('strip_low_logs')
    add_project_arguments('-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_INFO', language : 'cpp')
else
    add_project_arguments('-DSPDLOG_ACTIVE_LEVEL=SPDLOG_LEVEL_TRACE', language : 'cpp')
endif


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

executable(
    'afl-cassowire',
    sources,
    include_directories : include_dirs,
    dependencies : [yaml_cpp_dep, argparse_dep, spdlog_dep],
    link_args : link_args,
    install : true,
)
