# 设置CMake版本和最低要求
cmake_minimum_required(VERSION 3.10)

# 设置项目名称和版本
project(TestServer VERSION 1.0)

# 查找OpenSSL库
find_package(OpenSSL REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(GNUTLS REQUIRED gnutls)

# 设置编译选项
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -g")

# 添加可执行文件
add_executable(test_server test_server.c common.c)
add_executable(test_client test_client.c common.c)
add_executable(hello hello.c common.c)
add_executable(tls_nonblock tls_nonblock.c common.c)
add_executable(gnutls_ktls gnutls_ktls.c common.c)
add_executable(perf_test perf_test.c common.c)

# 链接OpenSSL库
target_link_libraries(test_server OpenSSL::SSL OpenSSL::Crypto ${GNUTLS_LIBRARIES})
target_link_libraries(test_client OpenSSL::SSL OpenSSL::Crypto ${GNUTLS_LIBRARIES})
target_link_libraries(hello ${GNUTLS_LIBRARIES})
target_link_libraries(tls_nonblock ${GNUTLS_LIBRARIES})
target_link_libraries(gnutls_ktls ${GNUTLS_LIBRARIES})
target_link_libraries(perf_test OpenSSL::SSL)

# 可选：添加安装目标（如果需要）
# install(TARGETS test_server DESTINATION bin)
