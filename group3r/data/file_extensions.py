"""File extension lists for classification.

Ported from Group3r/Options/AssessmentOptions/FileExtensions.cs
"""

# Executable and script file extensions
EXE_AND_SCRIPT_EXTENSIONS = [
    "exe",
    "msi",
    "bat",
    "cmd",
    "hta",
    "ps1",
    "vbs",
    "scr",
    "com",
    "psd1",
    "psm1",
    "lnk",  # not technically an executable but behaves like one
]

# Configuration file extensions
CONFIG_FILE_EXTENSIONS = [
    "config",
    "xml",
    "json",
    "ini",
    "rdp",
    "conf",
    "cnf",
]

# Office macro-enabled file extensions
OFFICE_MACRO_EXTENSIONS = [
    "dot",
    "dotm",
    "doc",
    "docm",
    "xlt",
    "xls",
    "xltm",
    "xlsm",
    "pot",
    "potm",
    "ppt",
    "pptm",
]

# Combined set of all interesting extensions for quick membership tests
ALL_INTERESTING_EXTENSIONS = set(
    EXE_AND_SCRIPT_EXTENSIONS + CONFIG_FILE_EXTENSIONS + OFFICE_MACRO_EXTENSIONS
)

# Interesting access rights tracked for assessment
# Ported from AssessmentOptions.cs InterestingRights list
INTERESTING_RIGHTS = [
    "Owner",
    "CREATE_CHILD",
    "GENERIC_WRITE",
    "GENERIC_ALL",
    "WRITE_ATTRIBUTES",
    "WRITE_PROPERTIES",
    "WRITE_PROPERTY",
    "APPEND_DATA",
    "WRITE_DATA",
    "ALL_ACCESS",
    "DELETE_CHILD",
    "CREATE_CHILD",
    "WRITE_TREE",
    "FILE_WRITE",
    "FILE_ALL",
    "KEY_WRITE",
    "KEY_ALL",
    "STANDARD_RIGHTS_ALL",
    "STANDARD_DELETE",
    "DELETE_TREE",
    "ADD_FILE",
    "ADD_SUBDIRECTORY",
    "CREATE_PIPE_INSTANCE",
    "WRITE",
    "CREATE_LINK",
    "SET_VALUE",
    "WRITE_DAC",
    "WRITE_OWNER",
    "SET_VALUE",
]

# De-duplicated set version for quick lookups
INTERESTING_RIGHTS_SET = set(INTERESTING_RIGHTS)
