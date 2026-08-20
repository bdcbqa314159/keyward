# Minimal consumer used by the `package` CI job to prove an INSTALLED keyward is
# actually usable — not just that install() ran without error. Doubles as the
# worked example for the README.
cmake_minimum_required(VERSION 3.21)
project(keyward_consumer_test CXX)
find_package(keyward REQUIRED)
add_executable(consumer main.cpp)
target_link_libraries(consumer PRIVATE keyward::keyward)
