using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Linq;
using System.Security.Cryptography;
using FinalMakeupExamLibrary;
using static FinalMakeupExamLibrary.FinalMakeupClass;

namespace MakeupExamTests
{
    [TestClass]
    public class FinalMakeupClassTests
    {
        [TestMethod]
        public void AesBinaryEncryptionAndDecryptionTest()
        {
            FinalMakeupClass testObject = new FinalMakeupClass();

            byte[] key = new byte[16] { 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13 };
            byte[] iv = new byte[16] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] data = new byte[18] { 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13 };

            //FOR ENCRYPTION
            //if you select padding mode zeros then you will see decrypted buffer end segment padded with zeros
            //if you select padding mode none then you should provide padding data to your input buffer
            //if you select PKCS7 or other padding length data included padding methods then result decrypted buffer padding will be trimmed

            byte[] enc = testObject.AesBinaryEncryption(data, key, iv, CipherMode.CBC, PaddingMode.PKCS7);
            byte[] dec = testObject.AesBinaryDecryption(enc, key, iv, CipherMode.CBC, PaddingMode.PKCS7);

            Assert.IsTrue(data.SequenceEqual(dec));

        }

        [TestMethod]
        public void HmacSha1Test()
        {
            byte[] key = new byte[20] { 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13 };
            byte[] data = new byte[18] { 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13 };

            byte[] expected = new byte[20] { 0x66, 0x13, 0xA4, 0xA7, 0xE1, 0x81, 0x80, 0x70, 0x03, 0x4D, 0xD6, 0x80, 0xD9, 0xDB, 0x1F, 0x97, 0xF3, 0x3D, 0x1F, 0x94 };

            FinalMakeupClass testObject = new FinalMakeupClass();
            byte[] hash = testObject.HmacSha1(data, key);

            Assert.IsTrue(expected.SequenceEqual(hash));

        }

        [TestMethod]
        public void Hex2BinTest()
        {
            string keyString = "1313131313131313131313131313131313131313";
            byte[] expected = new byte[20] { 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13 };
            FinalMakeupClass testObject = new FinalMakeupClass();
            byte[] actual = testObject.Hex2Bin(keyString);

            Assert.IsTrue(expected.SequenceEqual(actual));
        }

        [TestMethod]
        public void Bin2HexTest()
        {
            string expected = "1313131313131313131313131313131313131313";
            byte[] input = new byte[20] { 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13 };
            FinalMakeupClass testObject = new FinalMakeupClass();
            string actual = testObject.Bin2Hex(input);

            Assert.IsTrue(expected.SequenceEqual(actual));
        }

        [TestMethod]
        public void Sha256HashTest()
        {
            byte[] input = new byte[20] { 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13, 0x13 };
            byte[] expected = new byte[32] { 0x38, 0xBE, 0x44, 0x22, 0xAC, 0xF1, 0xE9, 0xEC, 0x4E, 0xA2, 0xE3, 0xCA, 0x06, 0xDD, 0x97, 0x14, 0x6F, 0x95, 0x0F, 0x2C, 0xB8, 0xF2, 0x8A, 0x28, 0xDB, 0x83, 0x1C, 0x18, 0x9B, 0x5C, 0x41, 0x50 };
            FinalMakeupClass testObject = new FinalMakeupClass();
            byte[] actual = testObject.Sha256Hash(input);

            Assert.IsTrue(expected.SequenceEqual(actual));
        }

        [TestMethod]
        public void DijsktraTest1()
        {
           
        FinalMakeupClass t = new FinalMakeupClass();

            t.WalkDijsktra( 0,  9, t.GenerateSampleGraphWeighted(), out int distance, out int[]  dist);

            Assert.AreEqual(dist[0], 0);
            Assert.AreEqual(dist[1], 4);
            Assert.AreEqual(dist[2], 12);
            Assert.AreEqual(dist[3], 19);
            Assert.AreEqual(dist[4], 21);
            Assert.AreEqual(dist[5], 11);
            Assert.AreEqual(dist[6], 9);
            Assert.AreEqual(dist[7], 8);
            Assert.AreEqual(dist[8], 14);

          
        }

        [TestMethod]
        public void DijsktraTest2()
        {

            FinalMakeupClass t = new FinalMakeupClass();

            t.WalkDijsktra(0, 9, t.GenerateSampleGraphUnweighted(), out int distance, out int[] dist);

            Assert.AreEqual(dist[0], 0);
            Assert.AreEqual(dist[1], 1);
            Assert.AreEqual(dist[2], 2);
            Assert.AreEqual(dist[3], 3);
            Assert.AreEqual(dist[4], 4);
            Assert.AreEqual(dist[5], 3);
            Assert.AreEqual(dist[6], 2);
            Assert.AreEqual(dist[7], 1);
            Assert.AreEqual(dist[8], 2);
        }


        [TestMethod]
        public void DijsktraTest3()
        {
            /* Let us create the example 
             graph discussed above */
            int[,] graph = new int[,] {{0,5,3,0,0,0,0,0,0},
                                   {0,0,2,0,3,0,1,0,0},
                                   {0,0,0,7,7,0,0,0,0},
                                   {2,0,0,0,0,6,0,0,0},
                                   {0,0,0,2,0,1,0,0,0},
                                   {0,0,0,0,0,0,0,0,0},
                                   {0,0,0,0,1,0,0,0,0},
                                   {0,0,0,0,0,0,0,0,0},
                                   {0,0,0,0,0,0,0,0,0}};
            FinalMakeupClass t = new FinalMakeupClass();

            t.WalkDijsktra(0, 9, graph, out int distance, out int[] dist);

            Assert.AreEqual(dist[0], 0);
            Assert.AreEqual(dist[1], 5);
            Assert.AreEqual(dist[2], 3);
            Assert.AreEqual(dist[3], 9);
            Assert.AreEqual(dist[4], 7);
            Assert.AreEqual(dist[5], 8);
            Assert.AreEqual(dist[6], 6);
          
        }



        [TestMethod]
        public void QLearningTest1()
        {
            /* Let us create the example 
             graph discussed above */
        
                 int ns = 12;

            //Created maze with reference CreateMaze
            int[][] FT = new int[ns][];

            for (int i = 0; i < ns; ++i) FT[i] = new int[ns];
            FT[0][1] = FT[0][4] = FT[1][0] = FT[1][5] = FT[2][3] = 1;
            FT[2][6] = FT[3][2] = FT[3][7] = FT[4][0] = FT[4][8] = 1;
            FT[5][1] = FT[5][6] = FT[5][9] = FT[6][2] = FT[6][5] = 1;
            FT[6][7] = FT[7][3] = FT[7][6] = FT[7][11] = FT[8][4] = 1;
            FT[8][9] = FT[9][5] = FT[9][8] = FT[9][10] = FT[10][9] = 1;
            FT[11][11] = 1;  // Goal



            FinalMakeupClass t = new FinalMakeupClass();

            t.TrainAndWalkQLearning(FT, 8, 11, out int[] path);


            Assert.AreEqual(path[0], 8);
            Assert.AreEqual(path[1], 9);
            Assert.AreEqual(path[2], 5);
            Assert.AreEqual(path[3], 6);
            Assert.AreEqual(path[4], 7);
            Assert.AreEqual(path[5], 11);

        }


        [TestMethod]
        public void QLearningTest2()
        {
            /* Let us create the example 
             graph discussed above */

            int ns = 12;

            //Created maze with reference CreateMaze
            int[][] FT = new int[ns][];

            for (int i = 0; i < ns; ++i) FT[i] = new int[ns];
            FT[0][1] = FT[0][2] = FT[1][0] = FT[1][5] = FT[2][3] = 1;
            FT[4][6] = FT[3][2] = FT[3][7] = FT[4][0] = FT[4][8] = 1;
            FT[5][1] = FT[5][6] = FT[5][9] = FT[6][2] = FT[6][5] = 1;
            FT[6][9] = FT[7][3] = FT[7][6] = FT[7][11] = FT[8][4] = 1;
            FT[8][9] = FT[9][5] = FT[9][8] = FT[9][10] = FT[10][9] = 1;
            FT[11][11] = 1;  // Goal



            FinalMakeupClass t = new FinalMakeupClass();

            t.TrainAndWalkQLearning(FT, 6, 11, out int[] path);


            Assert.AreEqual(path[0], 6);
            Assert.AreEqual(path[1], 2);
            Assert.AreEqual(path[2], 3);
            Assert.AreEqual(path[3], 7);
            Assert.AreEqual(path[4], 11);
           

        }

        [TestMethod]
        public void QLearningTest3()
        {
            /* Let us create the example 
             graph discussed above */

            int ns = 12;

            //Created maze with reference CreateMaze
            int[][] FT = new int[ns][];

            for (int i = 0; i < ns; ++i) FT[i] = new int[ns];
            FT[0][1] = FT[0][3] = FT[1][0] = FT[1][5] = FT[2][3] = 1;
            FT[4][6] = FT[3][2] = FT[3][7] = FT[4][0] = FT[4][8] = 1;
            FT[5][1] = FT[5][6] = FT[5][9] = FT[6][2] = FT[6][5] = 1;
            FT[6][7] = FT[7][3] = FT[7][6] = FT[7][11] = FT[8][4] = 1;
            FT[8][9] = FT[9][5] = FT[9][8] = FT[9][10] = FT[10][9] = 1;
            FT[11][11] = 1;  // Goal



            FinalMakeupClass t = new FinalMakeupClass();

            t.TrainAndWalkQLearning(FT, 0, 11, out int[] path);


            Assert.AreEqual(path[0], 0);
            Assert.AreEqual(path[1], 3);
            Assert.AreEqual(path[2], 7);
            Assert.AreEqual(path[3], 11);
           


        }


        [TestMethod]
        public void MusicBoxTest1()
        {

            double estimatedDuration = 12.00;

            double[] musicList = { 3.55, 4.05, 5.00, 2.45 };
            FinalMakeupClass t = new FinalMakeupClass();

            t.MusicBox( estimatedDuration,  musicList, out double[] selectedMusicIndexes);

            Assert.AreEqual(selectedMusicIndexes[0], 2.45);
            Assert.AreEqual(selectedMusicIndexes[1], 5.00);
            Assert.AreEqual(selectedMusicIndexes[2], 4.05);
        }

        [TestMethod]
        public void MusicBoxTest2()
        {

            double estimatedDuration = 15.00;
            double[] musicList = { 1.40, 3.60, 7.80, 2.03, 1.10, 5.06 };
            
            FinalMakeupClass t = new FinalMakeupClass();

            t.MusicBox(estimatedDuration, musicList, out double[] selectedMusicIndexes);

            Assert.AreEqual(selectedMusicIndexes[0], 1.10);
            Assert.AreEqual(selectedMusicIndexes[1], 2.03);
            Assert.AreEqual(selectedMusicIndexes[2], 7.80);
            Assert.AreEqual(selectedMusicIndexes[3], 3.60);
            
        }


        [TestMethod]
        public void MusicBoxTest3()
        {

            double estimatedDuration = 10.00;
            double[] musicList = { 1.02, 3.10, 1.40, 2.60,2.02,1.9 };

            FinalMakeupClass t = new FinalMakeupClass();

            t.MusicBox(estimatedDuration, musicList, out double[] selectedMusicIndexes);

            Assert.AreEqual(selectedMusicIndexes[0], 2.02);
            Assert.AreEqual(selectedMusicIndexes[1], 2.60);
            Assert.AreEqual(selectedMusicIndexes[2], 1.40);
            Assert.AreEqual(selectedMusicIndexes[3], 3.10);

        }


        [TestMethod]
        public void calculateOTP1()
        {

            string key = "NALKCGIFFPDYDCBZXIBH";

            int counter = 1625832121;


            FinalMakeupClass m = new FinalMakeupClass();

            m.calculateOTP(counter, key, out string result);


            Assert.AreEqual(result, "560231");
            
        }



        [TestMethod]
        public void calculateOTP2()
        {

            string key = "NALKCGIFFPDYDCBZXIBH";

            int counter = 1625833241;


            FinalMakeupClass m = new FinalMakeupClass();

            m.calculateOTP(counter, key, out string result);


            Assert.AreEqual(result, "529235");

        }

        [TestMethod]
        public void calculateOTP3()
        {
            //I defined a 20 byte key
            string key = "NALKCGIFFPDYDCBZXIBH";
            //integer counter this can be unix epoc
            int counter = 1625833352;


            FinalMakeupClass m = new FinalMakeupClass();

            m.calculateOTP(counter, key, out string result);


            Assert.AreEqual(result, "859522");

        }


    }
}
