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

-- apparently the 4096 bit tests are too much for travis

spec :: Spec
spec = do
  describe "keygen" $ do
    it "should generate 1024 bit key" $ do
      keygen 1024 135 260

    it "should generate 2048 bit key" $ do
      keygen 2048 263 516

    --it "should generate 4096 bit key" $ do
      --keygen 4096 519 1028

    it "should return Nothing for wrong bit key" $ do
      g <- newStdGen
      let key = RSA.keygen g 1000
      isNothing key `shouldBe` True

  describe "IO end to end" $ do
    it "should encrypt and decrypt file with 1024 bit key" $ do
      encryptAndDecrypt 1024

    it "should encrypt and decrypt file with 2048 bit key" $ do
      encryptAndDecrypt 2048

    --it "should encrypt and decrypt file with 4096 bit key" $ do
      --encryptAndDecrypt 4096

keygen :: Int -> Int -> Int -> Expectation
keygen sizeInBits expectedPk expectedSk = do
  g <- newStdGen
  let key = RSA.keygen g sizeInBits
  let (pk, sk) = fromJust key
  let pkLen = length $ unpack pk
  let skLen = length $ unpack sk
  pkLen `shouldSatisfy` (\x -> x `elem` [expectedPk-1..expectedPk+1])
  skLen `shouldSatisfy` (\x -> x `elem` [expectedSk-1..expectedSk+1])

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