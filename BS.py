#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Fri Jul 23 12:06:27 2021

@author: aida
"""


from random import randint
from NonMalleabililty import A
from random import randint
import elgamal
import AIDAelectionalgs
import copy

class BS_GAME:
    def __init__(self, voting_scheme, Adversary, candidates, security_parameter):
        self.voting_scheme = voting_scheme
        self.Adversary = Adversary
        self.candidates = candidates
        self.security_parameter = security_parameter
        self.betas = [0, 0]
        self.L = []

    def Oracle(self, v0, v1):

        v_beta = v0 if self.beta == 0 else v1
        b = self.voting_scheme.Vote(self.pk, v_beta, self.security_parameter)
        self.betas[v_beta] += 1
        self.L.append([b, v0, v1])
        return b
     
    def play(self):
        self.pk, self.sk = self.voting_scheme.Setup(self.security_parameter)
        self.beta = randint(0,1) #very secure random number generator lol
        print(self.beta)
        
        self.v0, self.v1 = self.Adversary.return_votes2(self.pk, self.security_parameter)
        
        bulletinBoard, self.adversary_votes = self.Adversary.construct_bulletin_board(self.voting_scheme, self.pk, self.security_parameter, self.v0, self.v1)
        
        e = self.voting_scheme.Partial_Tally(self.sk, bulletinBoard, self.security_parameter)

        g = self.Adversary.get_g(bulletinBoard, e)
        print('betas', self.betas)
        return g == self.beta and self.balanced(self.betas) #and self.v0 in self.candidates and self.v1 in self.candidates
    
    def balanced(self, betas):
        if betas[0] == betas[1]:
            return True
          
      
class HeliosSystem():
    def Setup(self, security_parameter):
        crypto = elgamal.Cryptosystem()
        
        #this is from the Helios repo, they set these values to be the following:
        p = 16328632084933010002384055033805457329601614771185955389739167309086214800406465799038583634953752941675645562182498120750264980492381375579367675648771293800310370964745767014243638518442553823973482995267304044326777047662957480269391322789378384619428596446446984694306187644767462460965622580087564339212631775817895958409016676398975671266179637898557687317076177218843233150695157881061257053019133078545928983562221396313169622475509818442661047018436264806901023966236718367204710755935899013750306107738002364137917426595737403871114187750804346564731250609196846638183903982387884578266136503697493474682071
        q = 61329566248342901292543872769978950870633559608669337131139375508370458778917
        g = 14887492224963187634282421537186040801304008017743492304481737382571933937568724473847106029915040150784031882206090286938661464458896494215273989547889201144857352611058572236578734319505128042602372864570426550855201448111746579871811249114781674309062693442442368697449970648232621880001709535143047913661432883287150003429802392229361583608686643243349727791976247247948618930423866180410558458272606627111270040091203073580238905303994472202930783207472394578498507764703191288249547659899997131166130259700604433891232298182348403175947450284433411265966789131024573629546048637848902243503970966798589660808533

        crypto.p, crypto.q, crypto.g = p, q, g
        keypair = crypto.generate_keypair()

        return keypair.pk, keypair.sk

    def Vote(self, pk, beta, security_parameter):
        
        public_key = elgamal.PublicKey()
        public_key.g, public_key.p, public_key.q, public_key.y = pk.g, pk.p, pk.q, pk.y
        
        
        question = {"answer_urls": ["http://example.com/alice"], "answers": ["alice", "bob"], "choice_type": "approval", "max": 1, "min": 0,"result_type": "absolute", "question": "Who Should be President?", "short_name": "President", "tally_type": "homomorphic"}
        ea = AIDAelectionalgs.EncryptedAnswer()

        answer_indexes = [beta] #how exactly am I casting the vote here
        
        fields = ea.fromElectionAndAnswer(question, answer_indexes, pk)
        return fields
                
    
    def Partial_Tally(self, secret_key, bulletin_board, security_parameter):
        
        answers=  ["alice", "bob"]
        tally = [0 for _ in answers]

        for i in range(len(bulletin_board)):
            for answer_num in range(len(answers)):
                tally[answer_num] = bulletin_board[i].choices[answer_num] * tally[answer_num]

        return tally
         
    def Recover(self, tally, secret_key, public_key, bulletin_board, security_parameter):
        sk = elgamal.SecretKey()
        sk.public_key = secret_key.pk
        sk.x = secret_key.x
        results = []
        DLogTable = AIDAelectionalgs.DLogTable(sk.public_key.g, sk.public_key.p)
        table = DLogTable.precompute(len(bulletin_board))

        for result in tally:
            dec_factor, proof = sk.decryption_factor_and_proof(result) #proof is unused here!
            plaintext = sk.decrypt(result, dec_factor)
            result = DLogTable.lookup(plaintext.m)
            results.append(result)
      
        return results    
    
class Adversary_BS(HeliosSystem):

    def return_votes2(self, public_key, security_parameter):        
        v0, v1 = A.return_votes(public_key, security_parameter)
        return v0, v1

#oracle call of the adversary    
    def construct_bulletin_board(self, system, public_key, security_parameter, v0, v1):
        challenge_ballot = Ballot_Secrecy.Oracle(v0, v1)
        bb, votes = A.construct_bulletin_board(system, challenge_ballot, public_key, security_parameter)
        challenge_ballot2 = Ballot_Secrecy.Oracle(v1, v0)
        bb2, votes2 = A.construct_bulletin_board(system, challenge_ballot2, public_key, security_parameter)
        return bb, votes

        
    def get_g(self, bulletin_board, e):
        electionOutcome = HeliosSystem.Recover(self, e, Ballot_Secrecy.sk, Ballot_Secrecy.pk, bulletin_board, security_parameter)
        g = A.get_g(electionOutcome, Ballot_Secrecy.adversary_votes)
        print(electionOutcome,Ballot_Secrecy.adversary_votes, g)
        return g
           
#Calls:

system = HeliosSystem()
ABS = Adversary_BS()
candidates = [0, 1]
security_parameter = 2048

Ballot_Secrecy = BS_GAME(system, ABS, candidates, security_parameter)    
Bool = Ballot_Secrecy.play()

print('the adversary won!') if Bool == True else print('long live democracy!')
