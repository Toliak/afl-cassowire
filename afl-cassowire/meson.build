project('afl-proxy', 'cpp',
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
thread_dep = dependency('threads')
yaml_cpp_dep = dependency('yaml-cpp', required : true)
argparse_dep = dependency('argparse', required : true)


# ---------------------------
include_dirs = include_directories('src')

sources = files(
    'src/main.cpp',
    'src/config.cpp',
    'src/process.cpp',
    'src/network.cpp',
    'src/utils.cpp',
)

executable('afl-proxy',
    sources,
    include_directories : include_dirs,
    dependencies : [thread_dep, yaml_cpp_dep, argparse_dep],
    install : true,
)
