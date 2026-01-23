add_library(WebBagWolfConnection WolfSslConnection.cpp)
target_link_libraries(WebBagWolfConnection PRIVATE wolfssl)

add_library(WebBagHttpClient HttpClient.cpp)
target_link_libraries(WebBagHttpClient PRIVATE WebBagWolfConnection)

add_executable(webbag main.cpp)
