module RSASpec
( spec
)
where

import Data.ByteString.Lazy (ByteString, unpack, writeFile)
import Data.Maybe (fromJust, isNothing)
import System.Process (callCommand)
import System.Random (newStdGen)
import Test.Hspec

import qualified RSA

spec :: Spec
spec = do
  describe "IO end to end" $ do
    it "should encrypt and decrypt file with 1024 bit key" $ do
      let pubKey = "rsa.pub"
      let prvKey = "rsa.prv"
      let plaintext = "plaintext"
      let ciphertext = "ciphertext"
      let decrypted = "decrypted"
      let contents = "some longer unaligned message idk"

      callCommand $ "echo " ++ contents ++ " > " ++ plaintext

      RSA.keygenIO 1024 pubKey prvKey
      RSA.encryptIO pubKey plaintext ciphertext
      RSA.decryptIO prvKey ciphertext decrypted

      result <- readFile decrypted
      callCommand $ "rm " ++ pubKey ++ " " ++ prvKey ++ " " ++ plaintext ++
        " " ++ciphertext ++ " " ++ " " ++ decrypted
      result `shouldBe` contents ++ "\n"

    it "should encrypt and decrypt file with 2048 bit key" $ do
      let pubKey = "rsa.pub"
      let prvKey = "rsa.prv"
      let plaintext = "plaintext"
      let ciphertext = "ciphertext"
      let decrypted = "decrypted"
      let contents = "some longer unaligned message idk"
  
      callCommand $ "echo " ++ contents ++ " > " ++ plaintext
  
      RSA.keygenIO 2048 pubKey prvKey
      RSA.encryptIO pubKey plaintext ciphertext
      RSA.decryptIO prvKey ciphertext decrypted
  
      result <- readFile decrypted
      callCommand $ "rm " ++ pubKey ++ " " ++ prvKey ++ " " ++ plaintext ++
        " " ++ciphertext ++ " " ++ " " ++ decrypted
      result `shouldBe` contents ++ "\n"

    it "should encrypt and decrypt file with 4096 bit key" $ do
      let pubKey = "rsa.pub"
      let prvKey = "rsa.prv"
      let plaintext = "plaintext"
      let ciphertext = "ciphertext"
      let decrypted = "decrypted"
      let contents = "some longer unaligned message idk"
    
      callCommand $ "echo " ++ contents ++ " > " ++ plaintext
    
      RSA.keygenIO 4096 pubKey prvKey
      RSA.encryptIO pubKey plaintext ciphertext
      RSA.decryptIO prvKey ciphertext decrypted
    
      result <- readFile decrypted
      callCommand $ "rm " ++ pubKey ++ " " ++ prvKey ++ " " ++ plaintext ++
        " " ++ciphertext ++ " " ++ " " ++ decrypted
      result `shouldBe` contents ++ "\n"