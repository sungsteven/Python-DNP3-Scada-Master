from time import sleep
from datetime import datetime
from tkinter.ttk import Labelframe
import serial
import binascii
import queue
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, END
from tkinter.font import NORMAL
import serial.tools.list_ports
import pydnp3_master.DNP3_SC.dnp3master as Dnp3master


__author__ = "Tao Sun"

class ToolTip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip_window = None

    def showtip(self, selected_cmd):
        if self.tip_window or not self.text:
            return
        # Check if the selected value matches the trigger value
        if selected_cmd  in {Dnp3master.DNP_Request.Read_Analog_Intput_Points.name,
                             Dnp3master.DNP_Request.Read_Binary_Input_Points.name,
                             Dnp3master.DNP_Request.Write_Control_Operation_Point.name,
                             Dnp3master.DNP_Request.Write_Analog_Output_Point.name}:
            if selected_cmd == Dnp3master.DNP_Request.Write_Control_Operation_Point.name:
                tooltip_text = '[(Trip|Close|Pulse_On|Pulse_Off|Latch_On|Latch_Off) Point_index]'
            elif selected_cmd == Dnp3master.DNP_Request.Write_Analog_Output_Point.name:
                tooltip_text = '[Variation Point_index New_value]'
            else:
                tooltip_text = 'Read all points: No argument;\nRead one point: Point_index;\nRead multiple points: [Variation Qualifier Range]'
        else:
            tooltip_text = self.text
        x, y, _cx, cy = self.widget.bbox("insert")
        x = x + self.widget.winfo_rootx() + 25
        y = y + cy + self.widget.winfo_rooty() + 25
        self.tip_window = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(1)
        tw.wm_geometry("+%d+%d" % (x, y))
        label = tk.Label(tw, text=tooltip_text, justify=tk.LEFT,
                            background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                            font=("tahoma", "8", "normal"))
        label.pack(ipadx=1)

    def hidetip(self):
        tw = self.tip_window
        self.tip_window = None
        if tw:
            tw.destroy()

padding = {'padx': 5, 'pady': 5, 'sticky': tk.W}
padding_aligned_ontop = {'padx': 5, 'pady': 2, 'sticky': tk.NW}
class SCADA_Master_GUI:
    def __init__(self, parent):
        self.parent = parent
        self.address = (52, 0)
        self.conn_frame = tk.LabelFrame(parent, width=400, height=100)
        self.configure_conn_frame()
        self.dnpMaster = None
        self.thread_1 = None
        self.thread_2 = None
        self.unsolicitedMsgQueue = queue.Queue()
        self.stopToThreadQueue = queue.Queue()
        self.stopFromThreadQueue = queue.Queue()
        self.conn_button = ttk.Button(self.conn_frame, text='Connect', command=self.connect_to_client)
        self.conn_button.grid(column=2, row=2, **padding)
        self.disconn_button = ttk.Button(self.conn_frame, text='Disconnect', command = lambda: self.disconnect_from_client(self.thread_1, self.thread_2))
        self.disconn_button.configure(state='disable')
        self.disconn_button.grid(column=3, row=2, **padding)
        
        self.style = ttk.Style()
        self.configure_style()

        self.dnp_msg_label = ttk.Label(parent, text='DNP Message Display')
        self.dnp_msg_label.grid(column=0, row=10, **padding)
        self.conn_status_val = tk.StringVar()
        self.conn_status_entry = tk.Entry(parent, width=105, textvariable=self.conn_status_val)
        self.conn_status_entry.grid(column=0, row=12, columnspan=3, **padding)
        self.tree = ttk.Treeview(parent, style='Custom.Treeview', height=12)
        self.scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree_item_index = 0
        self.configure_tree()
        self.cmd_frame = Labelframe(parent, width=500, height=300)
        self.configure_cmd_frame()
        self.start_time = datetime.now()
        
    def configure_cmd_frame(self):
        self.cmd_frame.grid(column=0, row=13, **padding)
        self.cmd_combo_label = ttk.Label(self.cmd_frame, text="Please select a DNP requisition command:")
        self.cmd_combo_label.grid(column=0, row=0, **padding)
        self.cmd_combo = ttk.Combobox(self.cmd_frame, width=40, state='readonly')
        self.cmd_combo.grid(column=0, row=1, **padding_aligned_ontop)
        self.cmd_combo['values'] = [dnp_req.name 
                            for dnp_req in Dnp3master.DNP_Request]
        self.cmd_combo.current(8)
        self.cmd_combo.bind('<<ComboboxSelected>>', self.req_change)
        self.issue_dnpreq_btn = ttk.Button(self.cmd_frame, text='Send Request', command=self.issue_request)
        self.issue_dnpreq_btn.grid(column=1, row=1, **padding_aligned_ontop)
        self.optional_arg = tk.StringVar()
        self.optional_arg_entry = ttk.Entry(self.cmd_frame, width=40, textvariable=self.optional_arg)
        self.optional_arg_entry.grid(column=0, row=2, columnspan=3, **padding_aligned_ontop)
        self.arg_combo = ttk.Combobox(self.cmd_frame, width=40, state='readonly')
        self.arg_combo.grid(column=0, row=2, **padding_aligned_ontop)
        self.arg_combo['values'] = [dnp_cmd.name for dnp_cmd in Dnp3master.DNP_Command]
        self.arg_combo.current(8)
        self.arg_combo.grid_forget()
        
        self.readout_label = ttk.Label(self.cmd_frame, text='Readout Per Solicited Request')
        self.readout_label.grid(column=2, row=0, **padding_aligned_ontop)
        self.readout_scroll = scrolledtext.ScrolledText(self.cmd_frame, wrap=tk.WORD, width=32, height=5)
        self.readout_scroll.config(state=NORMAL)
        self.readout_scroll.grid(column=2, row=2, columnspan=3, **padding_aligned_ontop)
        
        self.tooltip = ToolTip(self.optional_arg_entry, 'No argument required')
        self.optional_arg_entry.bind("<Enter>", lambda event: self.tooltip.showtip(self.cmd_combo.get()))
        self.optional_arg_entry.bind("<Leave>", lambda event: self.tooltip.hidetip())
        self.cmd_frame.grid_forget()
            
    def configure_style(self):
        self.style.element_create("Custom.Treeheading.border", "from", "default")
        self.style.layout("Custom.Treeview.Heading", [
            ("Custom.Treeheading.cell", {'sticky': 'nswe'}),
            ("Custom.Treeheading.border", {'sticky':'nswe', 'children': [
                ("Custom.Treeheading.padding", {'sticky':'nswe', 'children': [
                    ("Custom.Treeheading.image", {'side':'right', 'sticky':''}),
                    ("Custom.Treeheading.text", {'sticky':'we'})
                ]})
            ]}),
        ])
        self.style.configure("Custom.Treeview.Heading",
            background="blue", foreground="white", relief="flat")
        self.style.map("Custom.Treeview.Heading",
            relief=[('active','groove'),('pressed','sunken')])
        
    def configure_tree(self):
        self.tree['columns'] = ('Value')
        self.tree.column('#0', width=450)
        self.tree.column('Value', width=200)
        self.tree.heading('#0', text='Name')
        self.tree.heading('Value', text='Value')
        self.tree.grid(column=0, row=11, **padding)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(column=1, row=11, sticky='ns')

    def configure_conn_frame(self):
        self.conn_frame.grid(column=0, row=0, **padding)
        
        self.protocol_label = ttk.Label(self.conn_frame, text='DNP Communication Protocol')
        self.protocol_label.grid(column=0, row=1, **padding)
        
        self.protocol_combo = ttk.Combobox(self.conn_frame, width=10, state='readonly')
        self.protocol_combo.grid(column=0, row=2, **padding)
        self.protocol_combo['values'] = ('UDP', 'TCP', 'Serial')
        self.protocol_combo.current(0)
        
        self.dnp_address_label = ttk.Label(self.conn_frame, text='DNP Address')
        self.dnp_address_label.grid(column=0, row=3, **padding)
        self.dnp_address_val = tk.StringVar()
        self.dnp_address_val.set('52')
        self.dnp_address_entry = ttk.Entry(self.conn_frame, textvariable=self.dnp_address_val)
        self.dnp_address_entry.grid(column=1, row=3, **padding)
        
        self.client_ip_label = ttk.Label(self.conn_frame, text='Client IP Address')
        self.client_ip_label.grid(column=0, row=4, **padding)
        self.client_ip_val = tk.StringVar()
        self.client_ip_val.set('192.168.52.2')
        self.client_ip_val_entry = ttk.Entry(self.conn_frame, textvariable=self.client_ip_val)
        self.client_ip_val_entry.grid(column=1, row=4, **padding)
        
        self.client_port_label = ttk.Label(self.conn_frame, text='Client Port')
        self.client_port_label.grid(column=0, row=5, **padding)
        self.client_port_val = tk.StringVar()
        self.client_port_val.set('20000')
        self.client_port_val_entry = ttk.Entry(self.conn_frame, textvariable=self.client_port_val)
        self.client_port_val_entry.grid(column=1, row=5, **padding)
        
        self.master_ip_label = ttk.Label(self.conn_frame, text='Master IP Address')
        self.master_ip_label.grid(column=0, row=6, **padding)
        self.master_ip_val = tk.StringVar()
        self.master_ip_val.set('192.168.52.201')
        self.master_ip_val_entry = ttk.Entry(self.conn_frame, textvariable=self.master_ip_val)
        self.master_ip_val_entry.grid(column=1, row=6, **padding)
        
        self.master_port_label = ttk.Label(self.conn_frame, text='Master Port')
        self.master_port_label.grid(column=0, row=7, **padding)
        self.master_port_val = tk.StringVar()
        self.master_port_val.set('20001')
        self.master_port_val_entry = ttk.Entry(self.conn_frame, textvariable=self.master_port_val)
        self.master_port_val_entry.grid(column=1, row=7, **padding)
        
        self.comport_name_label = ttk.Label(self.conn_frame, text='Com Port Name')
        self.comport_name_label.grid(column=0, row=8, **padding)
        self.comport_name_combo = ttk.Combobox(self.conn_frame, width=10, state='readonly')
        self.comport_name_combo.grid(column=1, row=8, **padding)
        self.comport_name_combo['values'] = [port_tuple[0] 
                                             for port_tuple in serial.tools.list_ports.comports()]
        self.comport_name_combo.current(0)
        
        self.baudrate_label = ttk.Label(self.conn_frame, text='BaudRate')
        self.baudrate_label.grid(column=0, row=9, **padding)
        self.baudrate_val = tk.StringVar()
        self.baudrate_val.set('57600')
        self.baudrate_entry = ttk.Entry(self.conn_frame, textvariable=self.baudrate_val)
        self.baudrate_entry.grid(column=1, row=9, **padding)
        
    def add_items_to_treeview(self, table, title):
        table = {title: table}
        tree_item_list = []
        first_item = [-1, -1, table]
        buffer_list = [first_item]
        while buffer_list:
            first_item = buffer_list.pop()
            if isinstance(first_item[2], dict):
                for key, value in first_item[2].items():
                    if isinstance(value, dict):
                        buffer_list.append([first_item[1], self.tree_item_index, value])
                        tree_item_list.append([first_item[1], self.tree_item_index, key])
                    else:
                        tree_item_list.append([first_item[1], self.tree_item_index, (key, value)])
                    self.tree_item_index += 1
        for tree_item in tree_item_list:
            if tree_item[0] == -1:   # this is the root item, no parent
                self.tree.insert('', 'end', iid=tree_item[1], text=tree_item[2], values=(''), open=False)
            elif isinstance(tree_item[2], tuple):
                treeItem_val = tree_item[2][1]
                if isinstance(tree_item, int):
                    treeItem_val = str(treeItem_val)
                self.tree.insert(tree_item[0], 'end', iid=tree_item[1], text=tree_item[2][0], values=(treeItem_val,), open=False)
            else:
                self.tree.insert(tree_item[0], 'end', iid=tree_item[1], text=tree_item[2], values=(''), open=False)
        self.tree_item_index += len(tree_item_list)
        self.tree.yview_moveto(1)    # display the bottom of the table
       
    def connect_to_client(self):
        self.conn_button.config(cursor='watch')
        dnpAddress = int(self.dnp_address_entry.get())   # int type
        baudRateVal = 0
        if self.baudrate_entry.get().isnumeric():
            baudRateVal = int(self.baudrate_entry.get())
        self.dnpMaster = Dnp3master.dnp3master(dnp_address=dnpAddress, 
                                               client_ip=self.client_ip_val_entry.get(), 
                                               client_port=int(self.client_port_val_entry.get()), 
                                               master_ip=self.master_ip_val_entry.get(), 
                                               master_port=int(self.master_port_val_entry.get()), 
                                               buffer_size=1024, 
                                               method=self.protocol_combo.get().lower(), 
                                               com_port_name=self.comport_name_combo.get(), 
                                               baud_rate=baudRateVal)
        if self.dnpMaster is not None:
            self.cmd_frame.grid(column=0, row=13, **padding)
            self.dnpMaster.logger.setLevel("DEBUG")
            self.address = (dnpAddress, 0)

            if indicator := self.dnpMaster.run(self.conn_status_val):  # Connect to outstation
                self.conn_status_entry.configure(bg=indicator)
            if indicator == 'green':    # when connection is established
                self.thread_1 = threading.Thread(target=self.read_from_socket, daemon=True)
                self.thread_2 = threading.Thread(target=self.check_link_status, daemon=True)
                self.stopToThreadQueue.queue.clear()
                self.stopFromThreadQueue.queue.clear()
                self.thread_1.start()
                self.thread_2.start()
                for child in self.conn_frame.winfo_children():
                    if child.widgetName != 'ttk::label':
                        if child.cget('text') != 'Disconnect':
                            child.configure(state='disable')
                        else:
                            child.configure(state='enable')
                for item in self.tree.get_children():
                    self.tree.delete(item)
                # issue an operation command to reset link right after connection is established
                # Simulate selecting a value from cmd_combo
                self.cmd_combo.current(7)  # Select the item Issue_DNP_Command (index 7)
                # Simulate selecting a value from arg_combo
                self.arg_combo.current(8)  # Select the item Reset_Link (index 8)
                # Simulate clicking the button
                self.issue_dnpreq_btn.invoke()
                # set command to manual operation
                self.cmd_combo.current(8)   
                self.optional_arg_entry.grid(column=0, row=2, columnspan=3, **padding_aligned_ontop)
                self.arg_combo.grid_forget()
            else:   # when connection is not made
                self.conn_button.config(state='enable')
                self.disconn_button.config(state='disable')
                self.cmd_frame.grid_forget()
        self.conn_button.config(cursor='')
    
    def disconnect_from_client(self, *argv):
        self.disconn_button.config(cursor='watch')
        self.parent.update_idletasks()
        self.cmd_frame.grid_forget()
        self.stopToThreadQueue.put(self.conn_status_val)
        self.stopToThreadQueue.put(self.conn_status_val)
        for arg in argv:
            arg.join()
        self.stopFromThreadQueue.get(timeout=10.0)
        self.stopFromThreadQueue.get(timeout=10.0)
        if indicator := self.dnpMaster.quit(self.conn_status_val):
            self.conn_status_entry.configure(bg=indicator)
        self.disconn_button.config(cursor='')
        for child in self.conn_frame.winfo_children():
            if child.widgetName != 'ttk::label':
                if child.cget('text') == 'Disconnect':
                    child.configure(state='disable')
                else:
                    child.configure(state='enable')

    def get_all_children(self, item=""):
        children = self.tree.get_children(item)
        for child in children:
            children += self.get_all_children(child)
        return children
    
    def issue_request(self):
        # TODO
        # an else case may need to be added at the end of if/elif statements to handle other types of DNP requests
        selected_dnpreq = self.cmd_combo.get()
        optional_args = self.optional_arg_entry.get()
        dnp_cmd_args = self.arg_combo.get()
        userInputArray = optional_args.strip().split()
        dnp_request = Dnp3master.DNP_Request[selected_dnpreq]
        if dnp_request == Dnp3master.DNP_Request.Issue_DNP_Command:
            operation_param = Dnp3master.DNP_Command[dnp_cmd_args]
        elif dnp_request in  [Dnp3master.DNP_Request.Read_Binary_Output_Points, 
                              Dnp3master.DNP_Request.Read_Analog_Output_Points, 
                              Dnp3master.DNP_Request.Read_Counter_Points]:
            operation_param = None
        elif dnp_request in  [Dnp3master.DNP_Request.Read_Binary_Input_Points, 
                              Dnp3master.DNP_Request.Read_Analog_Intput_Points]:
            operation_param = userInputArray if userInputArray else None
        elif dnp_request == Dnp3master.DNP_Request.Write_Control_Operation_Point:
            operationStr = userInputArray[0]
            pointStr = userInputArray[1]
            operation_param = (Dnp3master.Operation[operationStr], int(pointStr))
        elif dnp_request == Dnp3master.DNP_Request.Write_Analog_Output_Point:
            # variation, point, newVal
            varStr = userInputArray[0]
            pointStr = userInputArray[1]
            newvalStr = userInputArray[2]
            operation_param = (int(varStr), int(pointStr), float(newvalStr))

        prmFunCode, obj_def = Dnp3master.TransmitFrame.dnpReq_generation(dnpReq=dnp_request, 
                                                              op_params=operation_param)
        appl_ctrl = Dnp3master.TransmitFrame.getApplCtrl(obj_def)
        datalink_ctrl = Dnp3master.TransmitFrame.getDataLinkReqCtrl(prmFunCode)
        table, table_title = self.dnpMaster.send(self.address, 
                                            appl_ctrl, 
                                            datalink_ctrl, 
                                            obj_def)
        if table_title:
            self.add_items_to_treeview(table, table_title)
            
    def req_change(self, event):
        """ handle the dnp requisition command changed event """
        if self.cmd_combo.get() == 'Issue_DNP_Command':
            self.optional_arg_entry.grid_forget()
            self.arg_combo.grid(column=0, row=2, **padding_aligned_ontop)
        else:
            self.arg_combo.grid_forget()    # add option argument to read/write single point value
            self.optional_arg_entry.grid(column=0, row=2, columnspan=3, **padding_aligned_ontop)       

    def read_from_socket(self):
        def receive_sequence():
            sequence_bytes = []
            for _ in range(5):  # assuming there are up to five segments for each sequence
                if (byte_data := self.dnpMaster.get()) == b'':
                    break
                sequence_bytes.append(byte_data)
                if is_final_fragment(byte_data):
                    break
            return sequence_bytes

        def is_final_fragment(byte_data):
            if len(byte_data) <= 10:
                return True
            fin_bit_val = f'{byte_data[10]:08b}'[::-1][7]
            return fin_bit_val == '1'

        def process_sequence(sequence_bytes):
                cat_seq_bytes = Dnp3master.ReceivedFrame.categorize_receivedBytes(sequence_bytes)
                header_str = 'Unsolicited' if cat_seq_bytes['Unsolicited Response'] else 'Solicited'
                for index, byte_data in enumerate(sequence_bytes):
                    seq_num_str = f", seq#{cat_seq_bytes['Sequence Number']}" if cat_seq_bytes['Sequence Number'] not in [253, 254] else ''
                    table_title = generate_table_title(header_str, index, len(sequence_bytes), self.address[0], seq_num_str)
                    print_response(header_str, byte_data, index, len(sequence_bytes))
                    if cat_seq_bytes['Unsolicited Response']:
                        manage_unsolicited_queue(self.unsolicitedMsgQueue, byte_data)
                    readout_frame = Dnp3master.ReceivedFrame.convert2frame(byte_data, index == 0)
                    self.add_items_to_treeview(readout_frame.__dict__, table_title)
                    if (readout_value := self.get_readout_value(readout_frame.__dict__)):
                        readout_title_text_list = table_title[(table_title.find("]") + 1):].strip().split()
                        display_title = readout_title_text_list[0] + ' ' + readout_title_text_list[-1]
                        self.readout_scroll.delete('1.0', END)
                        self.readout_scroll.insert(END, f'{display_title}\n{readout_value}')
                        # self.readout_scroll.yview(END)
                        # move the vertical scroll bar to top
                        self.readout_scroll.yview_moveto(0.0)
                    print('Done with this sequence reading!')
                handle_confirmation(cat_seq_bytes, self.address, self.dnpMaster)
            
        def generate_table_title(header_str, index, total, rtu_num, seq_num_str):
            timestamp = datetime.now().strftime('%m/%d/%Y %I:%M:%S.%f')[:-3]
            if total > 1:
                return f" [{timestamp}] {header_str} response ({index + 1} of {total}) from RTU[{rtu_num}]{seq_num_str}"
            else:
                return f" [{timestamp}] {header_str} response from RTU[{rtu_num}]{seq_num_str}"

        def print_response(header_str, byte_data, index, total):
            if total > 1:
                print(f'{header_str} response {index + 1} of {total} from outstation: {binascii.hexlify(byte_data)}')
            else:
                print(f'{header_str} response from outstation: {binascii.hexlify(byte_data)}')

        def manage_unsolicited_queue(queue, byte_data):
            if queue.qsize() == 1000:  # make sure the buffer is not overflowed (>1000 elements)
                queue.get()
            queue.put(byte_data)

        def handle_confirmation(cat_seq_bytes, address, socket_conn):
            if cat_seq_bytes['Confirmation Required']:
                send_confirmation(cat_seq_bytes, address, socket_conn)
            elif cat_seq_bytes['Sequence Number'] == 253:
                send_read_request(cat_seq_bytes, address, socket_conn)

        def send_confirmation(cat_seq_bytes, address, socket_conn):
            op_params = {'Function Codes': Dnp3master.Function_Code.CONFIRM, 'Object Info': []}
            table, table_title = socket_conn.send(
                address,
                applCtrlVal=cat_seq_bytes['Application Ctrl'] & 0xDF,
                datalinkCtrlVal=0xC4,
                objDefVal=op_params,
                notPrint=cat_seq_bytes['Unsolicited Response']
            )
            if table_title:
                self.add_items_to_treeview(table, table_title)

        def send_read_request(cat_seq_bytes, address, socket_conn):
            op_params = {'Function Codes': Dnp3master.Function_Code.READ, 'Object Info': []}
            table, table_title = socket_conn.send(
                address,
                applCtrlVal=0xC0,
                datalinkCtrlVal=Dnp3master.TransmitFrame.getDataLinkReqCtrl(cat_seq_bytes['Function Code']),
                objDefVal=op_params
            )
            if table_title:
                self.add_items_to_treeview(table, table_title)
                
        while True:
            if sequence_bytes := receive_sequence():
                process_sequence(sequence_bytes)
            if not self.stopToThreadQueue.empty():
                self.stopToThreadQueue.get()
                self.stopFromThreadQueue.put(False)
                break

    def check_link_status(self):
        dnp_request = Dnp3master.DNP_Request.Issue_DNP_Command
        operation_param = Dnp3master.DNP_Command.Link_Status
        prmFunCode, obj_def = Dnp3master.TransmitFrame.dnpReq_generation(dnpReq=dnp_request, op_params=operation_param)
        appl_ctrl = Dnp3master.TransmitFrame.getApplCtrl(obj_def)
        datalink_ctrl = Dnp3master.TransmitFrame.getDataLinkReqCtrl(prmFunCode)
        while True:
            sleep(1)
            passed_time = datetime.now() - self.start_time
            if passed_time.total_seconds() >= 120:
                table, table_title = self.dnpMaster.send(self.address, appl_ctrl, datalink_ctrl, obj_def)
                if table_title:
                    self.add_items_to_treeview(table, table_title)
                self.start_time = datetime.now()
            if not self.stopToThreadQueue.empty():
                self.stopToThreadQueue.get()
                self.stopFromThreadQueue.put(False)
                # socket_conn.quit(conn_status_val)
                break

    def get_readout_value(self, readout_dict:dict):
        if 'application_data' not in readout_dict:
            return '' 
        for key, value in readout_dict['application_data'].items():
            if key not in {'Control', 'Function', 'Internal Indicator'}:
                break
        return value['Object Data'] if (value and type(value) is dict and 'Object Data' in value) else ''
            

if __name__ == '__main__':
    window = tk.Tk()
    window.geometry('700x800')
    window.resizable(False, False)
    window.title('DNP3 SCADA Master Simulator')
    SCADA_MASTER_UI = SCADA_Master_GUI(window)
    window.mainloop()
