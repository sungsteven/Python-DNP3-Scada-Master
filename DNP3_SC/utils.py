from enum import Enum

transportIndex = 0
solicitRespSeqIndex = 0
unsolicitRespSeqIndex = 0
bytes_to_nextFrag = b''
object_data_tuple = (False, 0, 0)       # three tuple values are 'Continue Object':Boolean, 'Next Index':Int, 'Remaining Count':Int

PRM1FUNCTIONCODES = [
    ['Primary function code', 'Function code name', 'Service function', 'FCV bit', 'Response function codes'], 
    ['0', 'RESET_LINK_STATES', 'Reset of remote link', '0', '0 or 1'], 
    ['1', '-', 'Obsolete', '-', '15 or no response'], 
    ['2', 'TEST_LINK_STATES', 'Test function for link', '1', '0 or 1 (no response is '], 
    ['', '', '', '', 'acceptable if the link states'], 
    ['', '', '', '', 'are UnReset'], 
    ['3', 'CONFIRMED_USER_DATA', 'Deliver application data,', '1', '0 or 1'], 
    ['', '', 'confirmation requested', '', ''], 
    ['4', 'UNCONFIRMED_USER_DATA', 'Deliver application data,', '0', 'No Secondary Station Data'], 
    ['', '', 'confimation not requested', '', 'Link response'], 
    ['9', 'REQUEST_LINK_STATUS', 'Request status of link', '0', '11'], 
    ['5, 6, 7, 8, 10, 11, 12, 13, 14, 15', '-', 'Reserved', '-', '15 or no response']
    ]

GROUP_VARIATION_DICT = {
    "0": {
"209": "Device Attributes_Secure authentication",
"210": "Device Attributes_Number of security statistics per association",
"211": "Device Attributes_Identification of support for user-specific attributes",
"212": "Device Attributes_Number of master-defined data set prototypes",
"213": "Device Attributes_Number of outstation-defined data set prototypes",
"214": "Device Attributes_Number of master-defined data sets",
"215": "Device Attributes_Number of outstation-defined data sets",
"216": "Device Attributes_Maximum number of binary output objects per request",
"217": "Device Attributes_Local timing accuracy",
"218": "Device Attributes_Duration of time accuracy",
"219": "Device Attributes_Support for analog output events",
"220": "Device Attributes_Maximum analog outptu index",
"221": "Device Attributes_Number of analog outputs",
"222": "Device Attributes_Support for binary output events",
"223": "Device Attributes_Maximum binary output index",
"224": "Device Attributes_Number of binary outputs",
"225": "Device Attributes_Support for frozen counter events",
"226": "Device Attributes_Support for frozen counters",
"227": "Device Attributes_Support for counter events",
"228": "Device Attributes_Maximum counter index",
"229": "Device Attributes_Maximum counter points",
"230": "Device Attributes_Support for frozen analog inputs",
"231": "Device Attributes_Support for frozen analog input events",
"232": "Device Attributes_Maximum analog input index",
"233": "Device Attributes_Number of analog input points",
"234": "Device Attributes_Support for double-bit binary input events",
"235": "Device Attributes_Maximum double-bit binary index",
"236": "Device Attributes_Number of double-bit binary input points",
"237": "Device Attributes_Support for binary input events",
"238": "Device Attributes_Maximum binary input index",
"239": "Device Attributes_Number of binary input points",
"240": "Device Attributes_Maximum transmit fragment size",
"241": "Device Attributes_Maximum receive fragment size",
"242": "Device Attributes_Device manufacturer's software version",
"243": "Device Attributes_Device manufacturer's hardware version",
"245": "Device Attributes_User-assigned location name",
"246": "Device Attributes_User-assigned ID code/number",
"247": "Device Attributes_User-assigned device name",
"248": "Device Attributes_Device serial number",
"249": "Device Attributes_DNP3 subset and conformance",
"250": "Device Attributes_Device manufacturer's product name and model",
"252": "Device Attributes_Device manufacturer's name",
"254": "Device Attributes_Non-specific all attributes request",
"255": "Device Attributes_List of attribute variations"},
"1": {"1": "Binary Inputs_Packed format",
    "2": "Binary Inputs_With flags"},
"2": {"1": "Binary Input Events_Withtout time",
    "2": "Binary Input Events_With absolute time",
    "3": "Binary Input Events_With relative time"},
"3": {"1": "Double-bit Binary Inputs_Packed format",
    "2": "Double-bit Binary Inputs_With flags"},
"4": {"1": "Double-bit Binary Input Events_Withtout time",
    "2": "Double-bit Binary Input Events_With absolute time",
    "3": "Double-bit Binary Input Events_With relative time"},
"10": {"1": "Binary Outputs_Packed format",
    "2": "Binary Outputs_Output status with flags"},
"11": {"1": "Binary Output Events_Status without time",
    "2": "Binary Output Events_Status with time"},
"12": {"1": "Binary Output Commands_CROB",
    "2": "Binary Output Commands_PCB",
    "3": "Binary Output Commands_Pattern mask"},
"13": {"1": "Binary Output Command Events_Command status without time",
    "2": "Binary Output Command Events_Command status with time"},
"20": {"1": "Counters_32-bit with flag",
    "2": "Counters_16-bit with flag",
    "3": "Counters_32-bit with flag, delta",
    "4": "Counters_16-bit with flag, delta",
    "5": "Counters_32-bit without flag",
    "6": "Counters_16-bit without flag",
    "7": "Counters_32-bit without flag, delta",
    "8": "Counters_16-bit without flag, delta"},
"21": {"1": "Frozen Counters_32-bit with flag",
    "2": "Frozen Counters_16-bit with flag",
    "3": "Frozen Counters_32-bit with flag, delta",
    "4": "Frozen Counters_16-bit with flag, delta",
    "5": "Frozen Counters_32-bit with flag and time",
    "6": "Frozen Counters_16-bit with flag and time",
    "7": "Frozen Counters_32-bit with flag and time, delta",
    "8": "Frozen Counters_16-bit with flag and time, delta",
    "9": "Frozen Counters_32-bit without flag",
    "10": "Frozen Counters_16-bit without flag",
    "11": "Frozen Counters_32-bit without flag, delta",
    "12": "Frozen Counters_16-bit without flag, delta"},
"22": {"1": "Counters Events_32-bit with flag",
    "2": "Counters Events_16-bit with flag",
    "3": "Counters Events_32-bit with flag, delta",
    "4": "Counters Events_16-bit with flag, delta",
    "5": "Counters Events_32-bit with flag and time",
    "6": "Counters Events_16-bit with flag and time",
    "7": "Counters Events_32-bit with flag and time, delta",
    "8": "Counters Events_16-bit with flag and time, delta"},
"23": {"1": "Frozen Counters Events_32-bit with flag",
    "2": "Frozen Counters Events_16-bit with flag",
    "3": "Frozen Counters Events_32-bit with flag, delta",
    "4": "Frozen Counters Events_16-bit with flag, delta",
    "5": "Frozen Counters Events_32-bit with flag and time",
    "6": "Frozen Counters Events_16-bit with flag and time",
    "7": "Frozen Counters Events_32-bit with flag and time, delta",
    "8": "Frozen Counters Events_16-bit with flag and time, delta"},
"30": {"1": "Analog Inputs_32-bit with flag",
    "2": "Analog Inputs_16-bit with flag",
    "3": "Analog Inputs_32-bit without flag",
    "4": "Analog Inputs_16-bit without flag",
    "5": "Analog Inputs_Single-precision, floating-point with flag",
    "6": "Analog Inputs_Double-precision, floating-point with flag"},
"31": {"1": "Frozen Analog Inputs_32-bit with flag",
    "2": "Frozen Analog Inputs_16-bit with flag",
    "3": "Frozen Analog Inputs_32-bit with time-of-freeze",
    "4": "Frozen Analog Inputs_16-bit with time-of-freeze",
    "5": "Frozen Analog Inputs_32-bit without flag",
    "6": "Frozen Analog Inputs_16-bit without flag",
    "7": "Frozen Analog Inputs_Single-precision, floating-point with flag",
    "8": "Frozen Analog Inputs_Double-precision, floating-point with flag"},
"32": {"1": "Analog Input Events_32-bit without time",
    "2": "Analog Input Events_16-bit without time",
    "3": "Analog Input Events_32-bit with time",
    "4": "Analog Input Events_16-bit with time",
    "5": "Analog Input Events_Single-precision, floating-point without time",
    "6": "Analog Input Events_Double-precision, floating-point without time",
    "7": "Analog Input Events_Single-precision, floating-point with time",
    "8": "Analog Input Events_Double-precision, floating-point with time"},
"33": {"1": "Frozen Analog Input Events_32-bit without time",
    "2": "Frozen Analog Input Events_16-bit without time",
    "3": "Frozen Analog Input Events_32-bit with time",
    "4": "Frozen Analog Input Events_16-bit with time",
    "5": "Frozen Analog Input Events_Single-precision, floating-point without time",
    "6": "Frozen Analog Input Events_Double-precision, floating-point without time",
    "7": "Frozen Analog Input Events_Single-precision, floating-point with time",
    "8": "Frozen Analog Input Events_Double-precision, floating-point with time"},
"34": {"1": "Analog Input Reporting Deadbands_16-bit",
    "2": "Analog Input Reporting Deadbands_32-bit",
    "3": "Analog Input Reporting Deadbands_Single-precision, floating-point"},
    "40": {"1": "Analog Output Status_32-bit with flag",
    "2": "Analog Output Status_16-bit with flag",
    "3": "Analog Output Status_Single-precision, floating-point with flag",
    "4": "Analog Output Status_Double-precision, floating-point with flag"},
"41": {"1": "Analog Outputs_32-bit with flag",
    "2": "Analog Outputs_16-bit with flag",
    "3": "Analog Outputs_Single-precision, floating-point",
    "4": "Analog Outputs_Double-precision, floating-point"},
"42": {"1": "Analog Output Events_32-bit without time",
    "2": "Analog Output Events_16-bit without time",
    "3": "Analog Output Events_32-bit with time",
    "4": "Analog Output Events_16-bit with time",
    "5": "Analog Output Events_Single-precision, floating-point without time",
    "6": "Analog Output Events_Double-precision, floating-point without time",
    "7": "Analog Output Events_Single-precision, floating-point with time",
    "8": "Analog Output Events_Double-precision, floating-point with time"},
"43": {"1": "Analog Output Command Events_32-bit without time",
    "2": "Analog Output Command Events_16-bit without time",
    "3": "Analog Output Command Events_32-bit with time",
    "4": "Analog Output Command Events_16-bit with time",
    "5": "Analog Output Command Events_Single-precision, floating-point without time",
    "6": "Analog Output Command Events_Double-precision, floating-point without time",
    "7": "Analog Output Command Events_Single-precision, floating-point with time",
    "8": "Analog Output Command Events_Double-precision, floating-point with time"},
"50": {"1": "Time and Date_Absolute time",
    "2": "Time and Date_Absolute time and interval",
    "3": "Time and Date_Absolute time at last recorded time",
    "4": "Time and Date_Indexed absolute time and long interval"},
"51": {"1": "Time and Date common time-of-occurrences_Absolute time, synchronized",
    "2": "Time and Date common time-of-occurrences_Absolute time, unsynchronized"},
"52": {"1": "Time Delays_Coarse",
    "2": "Time Delays_Fine"},
"60": {"1": "Class Objects_Class 0 data",
    "2": "Class Objects_Class 1 data",
    "3": "Class Objects_Class 2 data",
    "4": "Class Objects_Class 3 data"},
"70": {"1": "File-Control_File identifier-superseded",
    "2": "File-Control_Authentication",
    "3": "File-Control_File command",
    "4": "File-Control_File command status",
    "5": "File-Control_File transport",
    "6": "File-Control_File transport status",
    "7": "File-Control_File descriptor",
    "8": "File-Control_File specification string"},
"80": {"1": "Internal Indications_Packed format"},
"81": {"1": "Device Storage_Buffer fill status"},
"82": {"1": "Device Profiles_Functions and indexes"},
"83": {"1": "Data Sets_Private registration object",
    "2": "Data Sets_Private registration object descriptor"},
"85": {"1": "Data Set Prototypes_With UUID"},
"86": {"1": "Data Set Descriptors_Data set contents",
    "2": "Data Set Descriptors_Characteristics",
    "3": "Data Set Descriptors_Point index attributes"},
"87": {"1": "Data Sets_Present value"},
"88": {"1": "Data Set Events_Snapshot"},
"90": {"1": "Applications_Identifier"},
"91": {"1": "Status of Requested Operations_Active configuration"},
"100": {"0": "Floating-point_None"},
"101": {"1": "Binary-coded Decimal Integers_Small",
    "2": "Binary-coded Decimal Integers_Medium",
    "3": "Binary-coded Decimal Integers_Large"},
"102": {"1": "Unsigned Integers_8-bit"},
"110": {"0": "Octet Strings_None"},
"111": {"0": "Octet String Events_None"},
"112": {"0": "Virtual Terminal Output Blocks_None"},
"113": {"0": "Virtual Terminal Event Data_None"},
"120": {"1": "Authentication_Challenge",
    "2": "Authentication_Reply",
    "3": "Authentication_Aggressive mode request",
    "4": "Authentication_Session key status request",
    "5": "Authentication_Session key status",
    "6": "Authentication_Session key change",
    "7": "Authentication_Error",
    "8": "Authentication_User certificate",
    "9": "Authentication_Message authentication code (MAC)",
    "10": "Authentication_User status change",
    "11": "Authentication_Update key change request",
    "12": "Authentication_Update key change reply",
    "13": "Authentication_Update key change",
    "14": "Authentication_Update key change signature",
    "15": "Authentication_Update key change confirmation"},
"121": {"1": "Securite Statistics_32-bit with flag"},
"122": {"1": "Securite Statistic Events_32-bit with flag",
    "2": "Securite Statistic Events_32-bit with flag and time"}}

interval_unit = {
    'The outstation does not repeat the action': 0,
    'Miliseconds': 1,
    'Seconds': 2,
    'Minutes': 3,
    'Hours': 4,
    'Days': 5,
    'Weeks': 6,
    'Months': 7,
    'Months on Same Day of Week from Start of Month': 8,
    'Months on Same Day of Week from End of Month': 9,
    'Seasons': 10,
}
interval_unit_keys = {v:k for (k, v) in interval_unit.items()}

object_prefix_codes = {
    'Objects are packed without an index prefix:0': 0,
    'Objects are prefixed with an index:1': 1,
    'Objects are prefixed with an index:2': 2,
    'Objects are prefixed with an index:4': 3,
    'Objects are prefixed with an object size:1': 4,
    'Objects are prefixed with an object size:2': 5,
    'Objects are prefixed with an object size:4': 6,
}
object_prefix_code_keys = {v:k for (k, v) in object_prefix_codes.items()}

range_specifier_codes = {
    'Range field contains 1-octet start and stop indexes:2': 0,
    'Range field contains 2-octet start and stop indexes:4': 1,
    'Range field contains 4-octet start and stop indexes:8': 2,
    'Range field contains 1-octet start and stop virtual addresses:2': 3,
    'Range field contains 2-octet start and stop virtual addresses:4': 4,
    'Range field contains 4-octet start and stop virtual addresses:8': 5,
    'No range field is used. This implies all values:0': 6,
    'Range field contains 1-octet count of objects:1': 7,
    'Range field contains 2-octet count of objects:2': 8,
    'Range field contains 4-octet count of objects:4': 9,
    'Variable format qualifier, range field contains 1-octet count of objects:1': 11
}
range_specifier_code_keys = {v:k for (k, v) in range_specifier_codes.items()}

class Function_Code(Enum):
    CONFIRM = 0
    READ = 1
    WRITE = 2
    SELECT = 3
    OPERATE = 4
    DIRECT_OPERATE = 5
    DIRECT_OPERATE_NR = 6
    IMMED_FREEZE = 7
    IMMED_FREEZE_NR = 8
    FREEZE_CLEAR = 9
    FREEZE_CLEAR_NR = 10
    FREEZE_AT_TIME = 11
    FREEZE_AT_TIME_NR = 12
    COLD_RESTART = 13
    WARM_RESTART = 14
    INITIALIZE_DATA = 15
    INITIALIZE_APPL = 16
    START_APPL = 17
    STOP_APPL = 18
    SAVE_CONFIG = 19
    ENABLE_UNSOLICITED = 20
    DISABLE_UNSOLICITED = 21
    ASSIGN_CLASS = 22
    DELAY_MEASURE = 23
    RECORD_CURRENT_TIME = 24
    OPEN_FILE = 25
    CLOSE_FILE = 26
    DELETE_FILE = 27
    GET_FILE_INFO = 28
    AUTHENTICATE_FILE = 29
    ABORT_FILE = 30
    ACTIVATE_CONFIG = 31
    AUTHENTICATE_REQ = 32
    AUTH_REQ_NO_ACK = 33
    RESPONSE = 129
    UNSOLICITED_RESPONSE = 130

class PRM1_Func_Code(Enum):
    RESET_LINK_STATES = 0
    TEST_LINK_STATES = 2
    CONFIRMED_USER_DATA = 3
    UNCONFIRMED_USER_DATA = 4
    REQUEST_LINK_STATUS = 9

class PRM0_Func_Code(Enum):
    ACK = 0
    NACK = 1
    LINK_STATUS = 11
    NOT_SUPPORTED = 15

class DNP_Request(Enum):
    Read_Binary_Input_Points = 0
    Read_Binary_Output_Points = 1
    Read_Analog_Intput_Points = 2
    Read_Analog_Output_Points = 3
    Read_Counter_Points = 4
    Write_Control_Operation_Point = 5
    Write_Analog_Output_Point = 6
    Issue_DNP_Command = 7
    Manual_Operation = 8

class Ctrl_Status_Code(Enum):
    SUCCESS = 0
    TIMEOUT = 1
    NO_SELECT = 2
    FORMAT_ERROR = 3
    NOT_SUPPORTED = 4
    ALREADY_ACTIVE = 5
    HARDWARE_ERROR = 6
    LOCAL = 7
    TOO_MANY_OBJS = 8
    NOT_AUTHORIZED = 9
    AUTOMATION_INHIBIT = 10
    PROCESSING_LIMITED = 11
    OUT_OF_RANGE = 12
    NOT_PARTICIPATING = 126
    UNDEFINED = 127

class Operation(Enum):
    Trip = 0
    Close = 1
    Pulse_On = 2
    Pulse_Off = 3
    Latch_On = 4
    Latch_Off = 5

class TCC_Code(Enum):
    Null = 0
    Close = 1
    Trip = 2
    Reserved = 3

class Op_Type_Code(Enum):
    Null = 0
    Pulse_On = 1
    Pulse_Off = 2
    Latch_On = 3
    Latch_Off = 4
    Undefined = 5

class DNP_Command(Enum):
    Enable_Unsolicited_Response = 0
    Disable_Unsolicited_Response = 1
    Class_1_2_3_0_Data = 2
    Class_1_Data = 3
    Class_2_Data = 4
    Class_3_Data = 5
    Class_0_Data = 6
    Link_Status = 7
    Reset_Link = 8
    Device_Attributes = 9
    Binary_Input_Status = 10
    Binary_Input_Change = 11
    Binary_Input_Changes_and_Current_States = 12
    Binary_Output_Status = 13
    Binary_Output_Event = 14
    Binary_Output_Command_Event = 15
    Binary_Counter = 16
    Frozen_Counter = 17
    Binary_Counter_Change = 18
    Frozen_Counter_Change = 19
    Analog_Input_Status = 20
    Frozen_Analog_Input = 21
    Analog_Change_Event = 22
    Frozen_Analog_Event = 23
    Analog_Output_Status = 24
    Analog_Output_Event = 25
    Analog_Output_Command_Event = 26
    Read_Analog_Deadbands = 27
    Security_Statistics = 28
    Security_Statistics_Events = 29
    Time_Synchronization = 30
    Clear_Restart = 31
    Warm_Restart = 32
    Cold_Restart = 33

class Operation_Mode(Enum):
    Get = 0
    Set = 1
    Initialize = 2

def transport_index_global(oper_mode=Operation_Mode.Get):
    global transportIndex
    if oper_mode == Operation_Mode.Initialize:
        transportIndex = 0
    else:
        transportIndex += 1
        if transportIndex  == 65:
            transportIndex = 0
    return max(transportIndex-1, 0)

def solicitRespSeq_index_global(oper_mode=Operation_Mode.Get):
    global solicitRespSeqIndex
    if oper_mode == Operation_Mode.Initialize:
        solicitRespSeqIndex = 0
    else:
        solicitRespSeqIndex += 1
        if solicitRespSeqIndex  == 17:
            solicitRespSeqIndex = 0
    return max(solicitRespSeqIndex-1, 0)

def unsolicitRespSeq_index_global(oper_mode=Operation_Mode.Get):
    global unsolicitRespSeqIndex
    if oper_mode == Operation_Mode.Initialize:
        unsolicitRespSeqIndex = 0
    else:
        unsolicitRespSeqIndex += 1
        if unsolicitRespSeqIndex  == 17:
            unsolicitRespSeqIndex = 0
    return max(unsolicitRespSeqIndex-1, 0)

def leftover_bytes_global(oper_mode=Operation_Mode.Get, new_val=b''):
    global bytes_to_nextFrag
    if oper_mode == Operation_Mode.Initialize:
        bytes_to_nextFrag = b''
        return b''
    elif oper_mode == Operation_Mode.Set:
        bytes_to_nextFrag = new_val
    return bytes_to_nextFrag

def object_data_tuple_global(oper_mode=Operation_Mode.Get, new_val=()):
    global object_data_tuple
    if oper_mode == Operation_Mode.Initialize:
        object_data_tuple = (False, 0, 0)
    elif oper_mode == Operation_Mode.Set:
        object_data_tuple = new_val
    return object_data_tuple

def init_all():
    transport_index_global(oper_mode=Operation_Mode.Initialize)
    solicitRespSeq_index_global(oper_mode=Operation_Mode.Initialize)
    unsolicitRespSeq_index_global(oper_mode=Operation_Mode.Initialize)
    leftover_bytes_global(oper_mode=Operation_Mode.Initialize)  
    object_data_tuple_global(oper_mode=Operation_Mode.Initialize)
    
if __name__ == '__main__':
    print(DNP_Request.Write_Control_Operation_Point.name)
    print(DNP_Request.Write_Control_Operation_Point.name == 'Write_Control_Operation_Point')