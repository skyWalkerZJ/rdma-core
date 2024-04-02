if (ENABLE_LTTNG AND LTTNGUST_FOUND)
  set(TRACE_FILE lingbo_trace.c)
endif()

rdma_provider(lingbo
  ${TRACE_FILE}
  lingbo.c
  )

if (ENABLE_LTTNG AND LTTNGUST_FOUND)
	target_include_directories("lingbo-rdmav${IBVERBS_PABI_VERSION}" PUBLIC ".")
	target_link_libraries("lingbo-rdmav${IBVERBS_PABI_VERSION}" LINK_PRIVATE LTTng::UST)
endif()
