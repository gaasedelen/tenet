CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config

TOOL_ROOTS := pintenet

$(OBJDIR)pintenet$(PINTOOL_SUFFIX): $(OBJDIR)pintenet$(OBJ_SUFFIX) $(OBJDIR)ImageManager$(OBJ_SUFFIX)
	$(LINKER) $(TOOL_LDFLAGS) $(LINK_EXE)$@ $^ $(TOOL_LPATHS) $(TOOL_LIBS)

include $(TOOLS_ROOT)/Config/makefile.default.rules
