**DNP3 SCADA Master In Python**

**Overview**

This project is a DNP3 SCADA Master implemented in Python. It provides a
graphical user interface (GUI) for simulating a SCADA master station
that communicates with outstations using the DNP3 protocol. The
simulator supports various DNP3 requests and commands, making it a
useful tool for testing and educational purposes.

**Features**

-   **GUI Interface**: Built using Tkinter, providing an intuitive and
    user-friendly interface.

-   **DNP3 Communication**: Supports UDP, TCP, and Serial communication
    protocols.

-   **Command Execution**: Allows issuing various DNP3 requests and
    commands, including reading and writing points.

-   **Real-time Data Display**: Displays DNP3 messages and responses in
    a tree view format.

-   **Tooltip Assistance**: Provides tooltips for command arguments to
    assist users in entering the correct parameters.

-   **Threaded Operations**: Uses threading for handling socket
    communication and link status checks.

-   **Utility Functions**: Includes various utility functions and
    enumerations for handling DNP3 operations and data.

-   **Frame Handling**: Implements classes for creating and parsing DNP3
    frames.

-   **Logging**: Provides detailed logging for monitoring communication
    and debugging.

**Installation**

1.  Clone the repository:

2.  git clone https://github.com/sungsteven/Tao-Python-Repo.git

3.  Navigate to the project directory:

4.  cd dnp3_scada_master

5.  Install the required dependencies:

6.  pip install -r requirements.txt

**Usage**

1.  Run the simulator:

2.  python dnp3_scada_master.py

3.  Use the GUI to configure the connection settings (protocol,
    addresses, ports, etc.).

4.  Connect to the client and start issuing DNP3 requests using the
    provided controls.

**GUI Components**

-   **Connection Frame**: Configure and manage the connection settings.

-   **Command Frame**: Select and issue DNP3 commands.

-   **Message Display**: View DNP3 messages and responses in real-time.

-   **Status Entry**: Display the connection status.

**Utility Functions**

The utils.py file contains various utility functions and enumerations
used in the simulator:

-   **Enumerations**: Defines various enums such
    as Function_Code, PRM1_Func_Code, DNP_Request, Ctrl_Status_Code, Operation, TCC_Code, Op_Type_Code,
    and DNP_Command.

-   **Global Variables**: Manages global variables
    like transportIndex, solicitRespSeqIndex, unsolicitRespSeqIndex, bytes_to_nextFrag,
    and object_data_tuple.

-   **Helper Functions**: Includes functions for managing global
    variables, such
    as transport_index_global, solicitRespSeq_index_global, unsolicitRespSeq_index_global, leftover_bytes_global,
    and object_data_tuple_global.

-   **Initialization**: Provides an init_all function to initialize all
    global variables.

**Frame Handling**

The dnp3_frame.py file contains classes and methods for handling DNP3
frames:

-   **TransmitFrame**: Represents a frame being sent out as a request.
    It includes methods for setting data blocks, calculating CRC,
    swapping bytes, and converting the frame to bytes.

-   **ReceivedFrame**: Represents a frame being received either upon
    request (solicited) or broadcasting (unsolicited). It includes
    methods for setting datalink headers, transport headers, application
    data, and reading various types of data from the frame.

-   **FrameError**: Custom exception class for handling frame-related
    errors.

**DNP3 Master**

The dnp3master.py file contains the main class for the DNP3 master:

-   **dnp3master**: Manages the connection to the outstation and handles
    sending and receiving DNP3 frames. It includes methods for running
    the connection, sending commands, receiving messages, and closing
    the connection.

-   **Logging**: Provides detailed logging for monitoring communication
    and debugging.

**Example**

Here\'s a brief example of how to use the simulator:

1.  Select the communication protocol (UDP, TCP, or Serial).

2.  Enter the DNP address, client IP, client port, master IP, and master
    port.

3.  Click \"Connect\" to establish a connection with the outstation.

4.  Select a DNP request from the dropdown menu and enter any required
    arguments.

5.  Click \"Send Request\" to issue the command and view the response in
    the message display area.

**Author**

-   **Tao Sun**

**License**

This project is licensed under the MIT License. See the LICENSE file for
details.
