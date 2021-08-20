#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jul 22 14:50:36 2021

@author: aida
"""
from random import randint
from secrets import randbelow
from collections import defaultdict

class NM_GAME:
    
    def __init__(self, votingScheme, Adversary, candidates, securityParameter):
        
        self.votingScheme = votingScheme
        self.Adversary = Adversary
        self.candidates = candidates
        self.securityParameter = securityParameter
        
    def play(self):
        """A series of interactions between the challenger and the adversary."""
        
        self.pk, self.sk = self.votingScheme.Setup(self.securityParameter)
        self.beta = randint(0,1) #very secure random number generator lol
        
        self.v0, self.v1 = self.Adversary.return_votes(self.pk, self.securityParameter)
        
        challengeBallot = self.votingScheme.Vote(self.pk, self.candidates[self.beta], self.securityParameter)
        #print('challenge ballot', challengeBallot)
        
        bulletinBoard = self.Adversary.construct_bulletin_board(challengeBallot, self.pk, self.securityParameter)
        
        evidence = self.votingScheme.Partial_Tally(self.sk, bulletinBoard, self.securityParameter)
        electionOutcome = self.votingScheme.Recover(bulletinBoard, evidence, self.pk)
        
        g = self.Adversary.get_g(electionOutcome)
        
        return g == self.beta and challengeBallot not in bulletinBoard and self.v0 in self.candidates and self.v1 in self.candidates

class Dummy_Voting_Scheme:
    def Setup(self, securityParameter):
        """The voting scheme has an initilaisation function to construct the public and private keys.
        This function is called with the security parameter as an input."""
        publicKey = 1
        secretKey = 2
        return publicKey, secretKey
    
    def Vote(self, publicKey, vote, securityParameter):
        """The Vote function constructs an encrypted ballot from the voter's vote"""
        encryptedVote = vote*publicKey #ballot shows vote (this is just a dummy encryption)
        nonce = randbelow(256)
        ballot = (encryptedVote, nonce)
        return ballot
    
    def Partial_Tally(self, secretKey, bulletinBoard, securityParameter):
        """Tally the ballots in the bulletin board. The ballots are constructed by the adversary."""
        evidence  = True #in helios this is some dlog equality
        #call here Helios' algs.py EGZKProof class
        return evidence
    
    def Recover(self, bulletinBoard, evidence, pk):
        """Compute the election outcome from the bulletin board"""
        #call here Helios' election outcome code
        electionOutcome = defaultdict(lambda:0)
        for i in bulletinBoard:
            vote = i[0]
            electionOutcome[vote] += 1
            print(electionOutcome)
        return electionOutcome
    
class Adversary:
    def return_votes(self, publicKey, securityParameter):
        """The adversary demands a challenge ballot is computed expressing a vote that is either v1 or v0"""
        v0, v1 = 1, 2 #hard coding this for the moment to be anything between {1,...,nc}
        return v0, v1
        
    def construct_bulletin_board(self, challengeBallot, publicKey, securityParameter): 
        #ideally this function would only take challengeBallot, but i cant compute a ballot without pk and k as inputs.
        """The adversary constructs a bulletin board, they have access to the challenge ballot but it is
        not included in the bulletin board"""
        #arbitrary many number of ballots constructed by the adversary:
        bb = set()
        for i in range(0, randint(2,10)):
            vote = randint(1,2)
            adversaryBallot = Dummy_Voting_Scheme.Vote(self, publicKey, vote, securityParameter)
            bb.add(adversaryBallot)
        print(bb)
        return bb
        
    def get_g(self, electionOutcome):
        """The adversary must determine what vote the challenge ballot contained. The guess g must equal
        beta (the challenger coin flip that determines which vote the challenge ballot is constructed for)"""
        g=1 #dumb adversary that always guesses 1. should win approx 50% of the time.
        return g
        
#Calls:

system = Dummy_Voting_Scheme()
A = Adversary()
candidates = [1, 2]
security_parameter = 2048

Non_Malleability = NM_GAME(system, A, candidates, security_parameter)    
Bool = Non_Malleability.play()

print('the adversary won!') if Bool == True else print('long live democracy!')
    
          
    