module RSAIntSpec
( spec
)
where

import Data.ByteString.Lazy (ByteString, unpack, writeFile)
import Data.Maybe (fromJust, isNothing)
import System.Process (callCommand)
import System.Random (newStdGen)
import Test.Hspec

import qualified RSA.API as RSA

spec :: Spec
spec = do
  describe "IO end to end" $ do
    it "should encrypt and decrypt file with 1024 bit key" $ do
      encryptAndDecrypt 1024

    it "should encrypt and decrypt file with 2048 bit key" $ do
      encryptAndDecrypt 2048

    it "should encrypt and decrypt file with 4096 bit key" $ do
      encryptAndDecrypt 4096

encryptAndDecrypt :: Int -> Expectation
encryptAndDecrypt keySize = do
  let pubKey = "rsa.pub"
  let prvKey = "rsa.prv"
  let plaintext = "plaintext"
  let ciphertext = "ciphertext"
  let decrypted = "decrypted"
  let contents = "some longer unaligned message idk"

  callCommand $ "echo " ++ contents ++ " > " ++ plaintext

  RSA.keygenIO keySize pubKey prvKey
  RSA.encryptIO pubKey plaintext ciphertext
  RSA.decryptIO prvKey ciphertext decrypted

  result <- readFile decrypted
  callCommand $ "rm " ++ pubKey ++ " " ++ prvKey ++ " " ++ plaintext ++
        " " ++ciphertext ++ " " ++ " " ++ decrypted
  result `shouldBe` contents ++ "\n"