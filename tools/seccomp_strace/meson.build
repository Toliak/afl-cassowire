project('strace_seccomp', 'cpp',
  default_options: [
    'cpp_std=c++20',
    'warning_level=3',
    'werror=true',
  ],
)

inc = include_directories('src')

sources = files(
    'src/main.cpp',
    'src/seccomp_filter.cpp',
    'src/target.cpp',
    'src/notifier.cpp',
    'src/trace.cpp',
)

strace_seccomp = executable(
  'strace_seccomp',
  sources,
  include_directories: inc,
  install: false,
)
