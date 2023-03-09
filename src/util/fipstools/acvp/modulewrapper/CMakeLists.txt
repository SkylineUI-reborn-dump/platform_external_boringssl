if(FIPS)
  add_executable(
    modulewrapper

    main.cc
    modulewrapper.cc
  )
<<<<<<< HEAD   (0a931c Snap for 8740412 from 2bbd592adbcc2fef5eb979af85d1e7b091f346)
  install(TARGETS modulewrapper)

  add_dependencies(modulewrapper global_target)

=======
>>>>>>> CHANGE (34340c external/boringssl: Sync to 8aa51ddfcf1fbf2e5f976762657e21c7)
  target_link_libraries(modulewrapper crypto)
endif()
