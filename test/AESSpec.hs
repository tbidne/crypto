module AESSpec
( spec
)
where

import Data.ByteString.Lazy (ByteString, unpack, writeFile)
import Data.Maybe (fromJust, isNothing)
import System.Process (callCommand)
import System.Random (newStdGen)
import Test.Hspec

import qualified AES

spec :: Spec
spec = do
  describe "keygen" $ do
    it "should generate 128 bit key" $ do
      g <- newStdGen
      let key = AES.keygen g 128
      let k = unpack $ fromJust key
      length k `shouldBe` 16
    
    it "should generate 192 bit key" $ do
      g <- newStdGen
      let key = AES.keygen g 192
      let k = unpack $ fromJust key
      length k `shouldBe` 24

    it "should generate 256 bit key" $ do
      g <- newStdGen
      let key = AES.keygen g 256
      let k = unpack $ fromJust key
      length k `shouldBe` 32

    it "should return Nothing for wrong bit key" $ do
      g <- newStdGen
      let key = AES.keygen g 100
      isNothing key `shouldBe` True

  describe "IO end to end" $ do
    it "should encrypt and decrypt file" $ do
      let keyFile = "key_256"
      let plaintext = "plaintext"
      let ciphertext = "ciphertext"
      let decrypted = "decrypted"
      let contents = "why hello there"

      callCommand $ "echo " ++ contents ++ " > " ++ plaintext

      AES.keygenIO 256 keyFile
      AES.encryptIO keyFile plaintext ciphertext
      AES.decryptIO keyFile ciphertext decrypted

      result <- readFile decrypted
      callCommand $ "rm " ++ keyFile ++ " " ++ plaintext ++ " " ++
                    ciphertext ++ " " ++ " " ++ decrypted
      result `shouldBe` contents ++ "\n"