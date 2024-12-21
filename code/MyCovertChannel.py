from CovertChannelBase import CovertChannelBase
import random
from scapy.all import sr1,IP, TCP, sniff
import socket
from multiprocessing import Process, Queue
import threading

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        
        pass


    def calculate_seq_number_difference(self, current_seq:int, seq_to_check:int):
        if seq_to_check < current_seq:
            seq_to_check = seq_to_check + 0xFFFFFFFF + 1
        return seq_to_check - current_seq


    def send_packet_calculating_seq_number(self, current_seq: int, number:int, dst:str = "receiver"):
        seq = (current_seq + number) % 0xFFFFFFFF
        p = IP(dst = dst) / TCP(seq = seq)
        super().send(p)
        return seq

    def send(self, log_file_name):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        #binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        binary_message = self.convert_string_message_to_binary("Naber.")
        current_seq = 0
        #Create a random seed for main random number generator
        random_seed = random.randint(0,10000)
        main_prng = random.Random(random_seed)
        secondary_prng = random.Random(random.randint(0,10000))
        #Send the seed to receiver
        
        print(random_seed)
        current_seq = self.send_packet_calculating_seq_number(current_seq,random_seed)
        #Choose a prime for validation
        prime_modulus_list = [7,11,13,17,23,29,31,37]
        prime_modulus = random.choice(prime_modulus_list)
        #Send the prime
        current_seq = self.send_packet_calculating_seq_number(current_seq,prime_modulus)
        import time
        #Send the message
        for char in binary_message:
            bit = int(char)
            number_to_send = 0
            real_message = main_prng.randint(0, 100000) % 100
            next_bit = False
            for i in range(50):
                fake_message = secondary_prng.randint(14, 100)
                if fake_message % prime_modulus == real_message % prime_modulus:
                    if fake_message % 2 == bit:
                        number_to_send = fake_message
                    else :
                        number_to_send = fake_message + prime_modulus
                    next_bit = True
                    break
            if not next_bit:
                if real_message % 2 == bit:
                    number_to_send = real_message
                else :
                    number_to_send = real_message + prime_modulus
            current_seq = self.send_packet_calculating_seq_number(current_seq, number_to_send)
           
        

    def packet_handler(self, packet):
        if packet.haslayer(TCP):
            # Get the TCP layer of the packet
            tcp_layer = packet[TCP]
            
            # Extract the sequence number
            seq_num = tcp_layer.seq
            return seq_num
        return -1


    def sniffProcess(self, queue: Queue):
        add_queue_func = lambda x : queue.put(self.packet_handler(x))
        sniff(
            iface = "eth0",
            filter = "tcp and src host sender",
            prn = add_queue_func
        )

    def receive(self, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        self.log_message("", log_file_name)
        #Start Listening
        pkt_queue = Queue()
        sniffProcess = Process(target=self.sniffProcess, kwargs={"queue": pkt_queue})
        sniffProcess.daemon = True
        sniffProcess.start()
        current_seq = 0
        # Get the seed from sender and establish random number generator
        seq_num = pkt_queue.get()
        random_seed = self.calculate_seq_number_difference(current_seq, seq_num)
        current_seq = seq_num
        main_prng = random.Random(random_seed)
        print("Random seed is: ",random_seed)
        #Get the prime modulus
        seq_num = pkt_queue.get()
        prime_modulus = self.calculate_seq_number_difference(current_seq, seq_num)
        current_seq = seq_num
        print(f"Prime modulus is : {prime_modulus}")
        #Start processing
        awaiting_number = main_prng.randint(0, 100000) % 100
        message = ""
        message = ""
        char = ""
        print(current_seq)
        while True:
            seq_num = pkt_queue.get()
            number = self.calculate_seq_number_difference(current_seq, seq_num)
            if number % prime_modulus == awaiting_number % prime_modulus:
                awaiting_number = main_prng.randint(0, 100000) % 100
                char = char + ("1" if number % 2 == 1 else "0")
                current_seq = seq_num
            if len(char) == 8:
                str_char = super().convert_eight_bits_to_character(char)
                message += str_char
                char = ""
                if str_char == '.':
                    print(message)
                    break
        sniffProcess.terminate()

        # Get the seed from sender and establish random number generator
