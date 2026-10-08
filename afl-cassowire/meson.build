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
thread_dep = dependency('threads') # TODO: do we really need this?
yaml_cpp_dep = dependency('yaml-cpp', required : true)
argparse_dep = dependency('argparse', required : true)
spdlog_dep = dependency('spdlog', required : true)

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
    'src/log.cpp',
    'src/process.cpp',
    'src/network.cpp',
    'src/utils.cpp',
)

executable(
    'afl-cassowire',
    sources,
    include_directories : include_dirs,
    dependencies : [thread_dep, yaml_cpp_dep, argparse_dep, spdlog_dep],
    install : true,
)
