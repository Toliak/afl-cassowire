project('cassowire-test-target', 'cpp',
    version : '0.1.0',
    default_options : [
        'cpp_std=c++23',
        'warning_level=3',
        'werror=false',
    ])

compiler = meson.get_compiler('cpp')

argparse_dep = dependency('argparse', required : true)

executable(
    'test-target',
    'src/test_target.cpp',
    dependencies : [argparse_dep],
)
