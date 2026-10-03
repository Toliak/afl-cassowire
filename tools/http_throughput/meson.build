project('http_throughput', 'cpp',
  default_options: [
    'cpp_std=c++20',
    'warning_level=3',
    'werror=true',
  ],
)

inc = include_directories('src')

sources = files(
    'src/main.cpp',
)

http_throughput = executable(
  'http_bench',
  sources,
  install: false,
)