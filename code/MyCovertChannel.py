from CovertChannelBase import CovertChannelBase
import random
from scapy.all import sr1,IP, TCP, sniff
from multiprocessing import Process, Queue

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        """
        
        pass


    def calculate_seq_number_difference(self, current_seq:int, seq_to_check:int):
        """
        - This function calculates the difference between two sequence numbers considering overflows.
        """
        if seq_to_check < current_seq:
            seq_to_check = seq_to_check + 0xFFFFFFFF + 1
        return seq_to_check - current_seq


    def send_packet_calculating_seq_number(self, current_seq: int, number:int, dst:str = "receiver"):
        """
        - This function sends a packet with the desired number.
        - Returns the new sequence number.
        """
        seq = (current_seq + number) % 0xFFFFFFFF
        p = IP(dst = dst) / TCP(seq = seq)
        super().send(p)
        return seq

    def send(self, log_file_name, seed: int, prime_modulus: int, dst:str = "receiver"):
        """
        - seed: int = should be an integer value to initialie a random number generator.  Should be the same as given to receive function.
        - prime_modulus: int = should be an integer value which is an odd prime number between 7 and 97. Should be the same as given to receive function.
        - dst: host name or ip address of the receiver. The default value is "receiver"
        - Creates a random binary message and send 2 bit by 2 bit covertly according to algorithm explained at README.md
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name,min_length=16,max_length=16)
        message = super().convert_string_message_to_binary(binary_message)
        current_seq = 0
        main_prng = random.Random(seed)
        secondary_prng = random.Random(random.randint(0,10000))
        real_message = main_prng.randint(8 * prime_modulus, 20 * prime_modulus)
        for i in range(int(len(binary_message)/2)):
            change_awaiting_number = False
            bit0 = int(binary_message[i*2])
            bit1 = int(binary_message[i*2+1])
            
            number_to_send = 0
            fake_message = secondary_prng.randint(8 * prime_modulus, 20 * prime_modulus)
            if bit0 == 0:
                while real_message % prime_modulus == fake_message % prime_modulus:
                    fake_message = secondary_prng.randint(8 * prime_modulus, 20 * prime_modulus)
                number_to_send = fake_message
            else:
                number_to_send = real_message + secondary_prng.randint(-5, 5) * prime_modulus
                change_awaiting_number = True
            are_evenness_same = (number_to_send % 2 == real_message % 2)
            if bit1 == 0:
                if are_evenness_same:
                    number_to_send += prime_modulus
            else:
                if not are_evenness_same:
                    number_to_send += prime_modulus   
            if change_awaiting_number:
                real_message = main_prng.randint(8 * prime_modulus, 20 * prime_modulus)
            current_seq = self.send_packet_calculating_seq_number(current_seq, number_to_send, dst)
        return message

    def packet_handler(self, packet):
        """
        - This function is used to extract the sequence number from the TCP packet.
        """
        if packet.haslayer(TCP):
            # Get the TCP layer of the packet
            tcp_layer = packet[TCP]
            
            # Extract the sequence number
            seq_num = tcp_layer.seq
            return seq_num
        return -1


    def sniffProcess(self, queue: Queue, src: str):
        """
         - This function is used to sniff the packets and put the sequence numbers to the queue.
        """
        add_queue_func = lambda x : queue.put(self.packet_handler(x))
        sniff(
            iface = "eth0",
            filter = f"tcp and src host {src}",
            prn = add_queue_func,
            store = False
        )

    def receive(self, log_file_name, seed: int, prime_modulus: int, src: str = "sender"):
        """
        - seed: int = should be an integer value to initialie a random number generator. Should be the same as given to send function.
        - prime_modulus: int = should be an integer value which is an odd prime number between 7 and 97.  Should be the same as given to send function.
        - src: host name or ip address of the sender. The default value is "sender"
        - Start sniffing packets on a process and puts them in a queue. Concurrently, the packets are processed and a message is formed.
        - When the dot character is received, the message is logged and returned.
        """
        self.log_message("", log_file_name)
        #Start Listening
        pkt_queue = Queue()
        sniffProcess = Process(target=self.sniffProcess, kwargs={"queue": pkt_queue, "src": src})
        sniffProcess.daemon = True
        sniffProcess.start()
        current_seq = 0
        main_prng = random.Random(seed)
        #Start processing
        awaiting_number = main_prng.randint(8 * prime_modulus, 20 * prime_modulus)
        message = ""
        message = ""
        char = ""
        while True:
            seq_num = pkt_queue.get()
            number = self.calculate_seq_number_difference(current_seq, seq_num)
            bit1 = "1" if (number % 2 == awaiting_number % 2) else "0"
            if number % prime_modulus == awaiting_number % prime_modulus:
                bit0 = "1"
                awaiting_number = main_prng.randint(8 * prime_modulus, 20 * prime_modulus)
            else:
                bit0 = "0"
            char += bit0 + bit1
            current_seq = seq_num
            if len(char) == 8:
                str_char = super().convert_eight_bits_to_character(char)
                message += str_char
                char = ""
                if str_char == '.':
                    break
        sniffProcess.terminate()
        super().log_message(message, log_file_name)
        return message
