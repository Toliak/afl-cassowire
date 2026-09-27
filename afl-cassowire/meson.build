project('afl-proxy', 'cpp',
    version : '0.1.0',
    default_options : [
        'cpp_std=c++17',
        'warning_level=3',
        'werror=false',
    ])

# Dependencies
thread_dep = dependency('threads')
yaml_cpp_dep = dependency('yaml-cpp', required : true)

# If fkyaml is not installed system-wide, use wrap:
# meson wrap install fkyaml

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
    dependencies : [thread_dep, yaml_cpp_dep],
    install : true,
)