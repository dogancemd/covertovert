import random


class Sender:
    def __init__(self, seed,seed2, upperLimit = 50):
        self.gen1 = random.Random(seed)
        self.gen2 = random.Random(seed2)
        self.upperLimit = 50
    def send_message(self,message):
        messages = list()
        for str_bit in str(message):
            bit = int(str_bit)
            real_message = self.gen1.randint(0, 100000) % 100
            next_bit = False
            for i in range(50):
                fake_message = self.gen2.randint(14, 100)
                if fake_message % 7 == real_message % 7:
                    if fake_message % 2 == bit:
                        messages.append(fake_message)
                    else :
                        messages.append(fake_message+7)
                    next_bit = True
                    break
                else:
                    messages.append(fake_message)
            if not next_bit:
                if real_message % 2 == bit:
                    messages.append(real_message)
                else :
                    messages.append(real_message+7)
        return messages


class Receiver:
    def __init__(self, seed):
        self.gen = random.Random(seed)
        self.awaiting_number = self.gen.randint(0, 100000) % 100 

    def receive(self, numbers):
        message = 0
        decoded_messages = list()
        awaiting_numbers = list()
        for number in numbers:
            if number % 7 == self.awaiting_number % 7:
                print(f"Received number: {number}, awaiting number: {self.awaiting_number}, received bit: {number % 2}")
                awaiting_numbers.append(self.awaiting_number)
                self.awaiting_number = self.gen.randint(0, 100000) % 100
                message = message * 10 + number % 2
                decoded_messages.append(number)
            else:
                print(f"Discarded message: {number}, awaiting number: {self.awaiting_number}")
        print(f"Received message: {message}")
        print(f"Awaiting numbers: {awaiting_numbers}")
        print(f"Decoded messages: {decoded_messages}")
        


if __name__ == "__main__":
    print("-"*169)
    first_seed = random.randint(0, 100000)
    second_seed = random.randint(0, 100000)
    sender = Sender(first_seed, second_seed, upperLimit=50)
    receiver = Receiver(first_seed)
    messages = sender.send_message("100")
    #print(messages)
    receiver.receive(messages)
