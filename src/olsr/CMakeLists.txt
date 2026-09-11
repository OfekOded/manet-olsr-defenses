build_lib(
  LIBNAME olsr
  SOURCE_FILES
    helper/olsr-helper.cc
    model/olsr-header.cc
    model/olsr-routing-protocol.cc
    model/olsr-state.cc
    # --- Security research extension ---
    # The defense-strategy interface plus the ONE defense this branch carries:
    # DCFM / GCOP (Schweitzer et al., Computer Communications 2024).
    # Each defense lives on its own branch -- see docs/ARCHITECTURE.md.
    model/olsr-defense-strategy.cc
    model/olsr-defense-gcop.cc
  HEADER_FILES
    helper/olsr-helper.h
    model/olsr-header.h
    model/olsr-repositories.h
    model/olsr-routing-protocol.h
    model/olsr-state.h
    model/olsr-defense-strategy.h
    model/olsr-defense-gcop.h
  LIBRARIES_TO_LINK
    ${libinternet}
    ${libwifi}            # PHY/MAC access for the promiscuous sniffer
    ${libtraffic-control} # QueueDisc monitoring
  TEST_SOURCES
    test/regression-test-suite.cc
    test/bug780-test.cc
    test/hello-regression-test.cc
    test/olsr-header-test-suite.cc
    test/olsr-routing-protocol-test-suite.cc
    test/tc-regression-test.cc
)
