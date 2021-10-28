import datetime
import hashlib
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

####################################################################################################################################################

blockchain = None
publickeylist = {}
mempool = []

####################################################################################################################################################

class Block:

    def __init__(self,previousblock,txdata):
        if previousblock == None:
            self.index = 0
            self.timestamp = datetime.datetime.now()
            self.data = txdata
            self.previoushash = None
            self.currenthash = hashlib.sha256(self.__merge_genesis_block_header().encode())
            self.__reveal_genesis_block_details()
        else:
            self.index = previousblock.index + 1
            self.timestamp = datetime.datetime.now()
            self.data = txdata
            self.previoushash = previousblock.currenthash
            self.currenthash = hashlib.sha256(self.__merge_block_header().encode())
            self.__reveal_block_details()

    def __merge_genesis_block_header(self):
        return str(self.index) + str(self.timestamp) + str(self.data) + str(self.previoushash)

    def __merge_block_header(self):
        return str(self.index) + str(self.timestamp) + str(self.data) + self.previoushash.hexdigest()

    def __reveal_genesis_block_details(self):
        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
        print("Block #",self.index)
        print("Created: " + str(self.timestamp))
        print("Data: " + str(self.data))
        print("Previous Block Hash: "+ str(self.previoushash))
        print("Current Block Hash: " + self.currenthash.hexdigest())
        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

    def __reveal_block_details(self):
        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")
        print("Block #",self.index)
        print("Created: " + str(self.timestamp))
        print("Data:\n" + str(self.data))
        print("Previous Block Hash: "+ self.previoushash.hexdigest())
        print("Current Block Hash: " + self.currenthash.hexdigest())
        print("--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------")

####################################################################################################################################################

class Chain:

    def __init__(self):
        print("Welcome to your own private blockchain_demo!\nCreating Genesis Block...")
        self.latestblock = Block(None,"This is the genesis block.")
        print("Genesis block successfully created!\nCongratulations! blockchain_demo is now initialized.\n")

    def create_block(self):
        print("Trying to create a block...")
        self.blocktxdata = ""
        self.verified = 0
        self.invalid = []
        for i in range(5):
            self.__verify_data(mempool[i])
        if self.verified != 5:
            print("All transactions could not be verified.")
            for i in self.invalid:
                del mempool[i]
            return
        print("All transactions verified. Creating a new block...")
        self.latestblock = Block(self.latestblock,self.blocktxdata)
        mempool.clear()


    def __verify_data(self,txdatawithsign):
        print("Verifying Transaction...")
        self.txdatawithoutsign = str(txdatawithsign[0])+" "+txdatawithsign[1].export_key(format='PEM')+" "+txdatawithsign[2].export_key(format='PEM')
        self.hash = SHA256.new(self.txdatawithoutsign.encode())
        self.checker = DSS.new(txdatawithsign[1],'fips-186-3')
        try:
            self.checker.verify(self.hash,txdatawithsign[3])
            self.verified = self.verified + 1
            self.blocktxdata = str(self.blocktxdata)+str(txdatawithsign[0])+"\n"+txdatawithsign[1].export_key(format='PEM')+"\n"+txdatawithsign[2].export_key(format='PEM')+"\n"+txdatawithsign[3].hex()+"\n\n"
            print("Transaction successfully verified.")
        except ValueError:
            print("This transaction is invalid.Deleting...")
            self.invalid.append(mempool.index(txdatawithsign))

####################################################################################################################################################

class Client:

    def __init__(self,name):
        print("Welcome! ",name,".")
        self.name = name
        print("Generating a private key for you...\nYour private key belongs to only you.\nNever share or disclose it with anybody.\nEven we do not have any copy of your private key.\nPlease take good care of your private key.")
        self.__generate_private_key()
        print("Private key generated.\nRevealing to you for this time only.")
        print(self.__reveal_private_key())
        print("\nNow generating a public key for you.")
        publickeylist[self.name] =  self.__generate_public_key()
        print(publickeylist[self.name].export_key(format='PEM'))
        print("\n")

    def __generate_private_key(self):
        file = open(self.name+'_privatekey.pem', 'wt')
        file.write(ECC.generate(curve='P-256').export_key(format='PEM'))
        file.close()

    def __reveal_private_key(self):
        file = open(self.name + '_privatekey.pem', 'rt')
        print(ECC.import_key(file.read()).export_key(format='PEM'))
        file.close()

    def __generate_public_key(self):
        return ECC.import_key(open(self.name+'_privatekey.pem','rt').read()).public_key()

    def initiate_transaction(self,amount,recepient):
        self.__push_data(amount,recepient)

    def __push_data(self,amount,recepient):
        self.txdatawithoutsign = str(amount)+" "+publickeylist[self.name].export_key(format='PEM')+" "+publickeylist[recepient.name].export_key(format='PEM')
        mempool.append([amount,publickeylist[self.name],publickeylist[recepient.name],self.__sign_data(self.txdatawithoutsign)])
        if len(mempool) ==5:
            print("Verifying transactions to create new block...")
            blockchain.create_block()

    def __sign_data(self,txdatawithoutsign):
        self.hash = SHA256.new(txdatawithoutsign.encode())
        return DSS.new(ECC.import_key(open(self.name+'_privatekey.pem','rt').read()),'fips-186-3').sign(self.hash)

####################################################################################################################################################

blockchain = Chain()

####################################################################################################################################################

# Add clients --- <clientname> = Client(<name>)
#Initiate transactions --- <clieantname>.initiate_transaction(amount,<clientname>)
#Tamper with transaction data --- mempool[][] = tamperedvalue //Look out for out of bound index

client1 = Client("Israt Mahzabeen")
client2 = Client("Moumita Yeasmin")
client3 = Client("Promee Shankar Kundu")
client4 = Client("Tasnim Tamim")
client1.initiate_transaction(20,client2)
client1.initiate_transaction(20,client3)
mempool[1][0] = 50
client1.initiate_transaction(22,client4)
client1.initiate_transaction(25,client3)
client1.initiate_transaction(30,client2)
client5 = Client("Mohammad Samin-Al-Wasee")
client6 = Client("Sameha Kamrul")
client7 = Client("Ziaur Rehman")
client8 = Client("Hasan Al Banna")
client3.initiate_transaction(20,client2)
client2.initiate_transaction(40,client3)
client1.initiate_transaction(22,client7)
client2.initiate_transaction(45,client6)
client7.initiate_transaction(30,client4)
client7.initiate_transaction(35,client5)


