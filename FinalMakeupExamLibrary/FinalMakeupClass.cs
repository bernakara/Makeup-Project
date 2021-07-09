using System;
using System.Text;
using System.Security.Cryptography;
using System.IO;
using System.Collections.Generic;

namespace FinalMakeupExamLibrary
{
    public class FinalMakeupClass
    {
       

        /// <summary>
        /// (Helper for Problems)
        /// Converts Hexadecimal String to Binary Byte Array
        /// </summary>
        /// <param name="hexString">Hexadecimal String</param>
        /// <returns>Byte Array</returns>
        public byte[] Hex2Bin(String hexString)
        {
            byte[] retval = new byte[hexString.Length / 2];
            for (int i = 0; i < hexString.Length; i += 2)
                retval[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
            return retval;
        }

        /// <summary>
        /// (Helper for Problems)
        /// Converts Binary Byte Array to Hexadecimal String without Seperator
        /// </summary>
        /// <param name="data">Binary Data</param>
        /// <returns>Hexadecimal String</returns>
        public string Bin2Hex(byte[] data)
        {
            return Bin2Hex(data, "");
        }

        /// <summary>
        /// (Helper for Problems)
        /// Convert Binary Byte Array to Hexadecimal String with Selected Seperator
        /// </summary>
        /// <param name="data">Binary Byte Array</param>
        /// <param name="separator">Seperator Character or String Such As : , - </param>
        /// <returns>Hexadecimal String</returns>
        public string Bin2Hex(byte[] data, string separator)
        {
            StringBuilder sb = new StringBuilder();
            for (int t = 0; t < data.Length; t++)
            {
                sb.AppendFormat("{0:X2}", data[t]);
                if (t < (data.Length - 1))
                {
                    sb.Append(separator);
                }
            }
            return sb.ToString();
        }

        /// <summary>
        /// (Helper for Problems)
        /// H-MAC SHA-1 binary hash calculation
        /// </summary>
        /// <param name="data">input binary data</param>
        /// <param name="key">20 bytes length binary key data</param>
        /// <returns></returns>
        public byte[] HmacSha1(byte[] data, byte[] key)
        {
            using (var hmacsha1 = new HMACSHA1(key))
            {
                var hash = hmacsha1.ComputeHash(data);
                return hash;
            }
        }

        /// <summary>
        /// (Helper for Problems)
        /// Calculate Binary Data SHA256 hash
        /// </summary>
        /// <param name="data">Binary Data Buffer</param>
        /// <returns>32 bytes SHA256 Hash</returns>
        public byte[] Sha256Hash(byte[] data)
        {
            using (SHA256 sha256hash = SHA256.Create())
            {
                var hash = sha256hash.ComputeHash(data);
                return hash;
            }
        }

        /// <summary>
        /// (Helper for Problems)
        /// AES Binary Encryption Function Returns Encrypted Byte Array,
        /// You should select correct key, iv , ciphermode such as CBC or ECB and padding modes
        /// </summary>
        /// <param name="data">clear buffer</param>
        /// <param name="key">16 bytes AES key buffer </param>
        /// <param name="iv">16 bytes IV buffer</param>
        /// <param name="cipherMode">AES Algorithm Cipher Modes CBC/ECB</param>
        /// <param name="paddingMode">AES Algorithm Padding Modes None/Zeros etc.</param>
        /// <returns>Encrypted buffer</returns>
        public byte[] AesBinaryEncryption(byte[] data, byte[] key, byte[] iv, CipherMode cipherMode, PaddingMode paddingMode)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = paddingMode;
                aes.Mode = cipherMode;

                aes.Key = key;
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, encryptor);
                }
            }
        }
        /// <summary>
        /// (Helper for Problems)
        /// AES Binary Decryption Function Returns Decrypted Byte Array,
        /// You should select correct key, iv , ciphermode such as CBC or ECB and padding modes
        /// </summary>
        /// <param name="data">AES encrypted buffer</param>
        /// <param name="key">16 bytes AES key buffer </param>
        /// <param name="iv">16 bytes IV buffer</param>
        /// <param name="cipherMode">AES Algorithm Cipher Modes CBC/ECB</param>
        /// <param name="paddingMode">AES Algorithm Padding Modes None/Zeros etc.</param>
        /// <returns>Decrypted buffer</returns>
        public byte[] AesBinaryDecryption(byte[] data, byte[] key, byte[] iv, CipherMode cipherMode, PaddingMode paddingMode)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 128;
                aes.BlockSize = 128;
                aes.Padding = paddingMode;
                aes.Mode = cipherMode;

                aes.Key = key;
                aes.IV = iv;

                using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                {
                    return PerformCryptography(data, decryptor);
                }
            }
        }
        /// <summary>
        /// (Helper for Problems)
        /// Performs CryptoStream Operation for Selected Algorithm Such as AES, DES
        /// </summary>
        /// <param name="data">Cryptographic Operation Input This Can Be Encrypted or Clear</param>
        /// <param name="cryptoTransform">Interface of Basic Cryptographic Operations </param>
        /// <returns></returns>
        private byte[] PerformCryptography(byte[] data, ICryptoTransform cryptoTransform)
        {
            using (var ms = new MemoryStream())
            using (var cryptoStream = new CryptoStream(ms, cryptoTransform, CryptoStreamMode.Write))
            {
                cryptoStream.Write(data, 0, data.Length);
                cryptoStream.FlushFinalBlock();

                return ms.ToArray();
            }
        }
        /// <summary>
        /// (Helper for Problems)
        /// Sample Adjency Matrix with Weights
        /// </summary>
        /// <returns>Sample Weighted Graph as 2D int array</returns>
        public int[,] GenerateSampleGraphWeighted()
        {
            int[,] graph = new int[,] { { 0, 4, 0, 0, 0, 0, 0, 8, 0 },
                                      { 4, 0, 8, 0, 0, 0, 0, 11, 0 },
                                      { 0, 8, 0, 7, 0, 4, 0, 0, 2 },
                                      { 0, 0, 7, 0, 9, 14, 0, 0, 0 },
                                      { 0, 0, 0, 9, 0, 10, 0, 0, 0 },
                                      { 0, 0, 4, 14, 10, 0, 2, 0, 0 },
                                      { 0, 0, 0, 0, 0, 2, 0, 1, 6 },
                                      { 8, 11, 0, 0, 0, 0, 1, 0, 7 },
                                      { 0, 0, 2, 0, 0, 0, 6, 7, 0 } };

            return graph;
        }

        public void TrainAndWalkQLearning(int[,] graph, int v1, int v2, out int[] path)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// (Helper for Problems)
        /// Sample Adjency Matrix without Weights
        /// </summary>
        /// <returns>Sample Unweighted Graph as 2D int array</returns>
        public int[,] GenerateSampleGraphUnweighted()
        {
            int[,] graph = new int[,] { { 0, 1, 0, 0, 0, 0, 0, 1, 0 },
                                      { 1, 0, 1, 0, 0, 0, 0, 1, 0 },
                                      { 0, 1, 0, 1, 0, 1, 0, 0, 1 },
                                      { 0, 0, 1, 0, 1, 1, 0, 0, 0 },
                                      { 0, 0, 0, 1, 0, 1, 0, 0, 0 },
                                      { 0, 0, 1, 1, 1, 0, 1, 0, 0 },
                                      { 0, 0, 0, 0, 0, 2, 0, 1, 1 },
                                      { 1, 1, 0, 0, 0, 0, 1, 0, 1 },
                                      { 0, 0, 1, 0, 0, 0, 1, 1, 0 } };

            return graph;
        }



        #region Q-Learning

        /// <summary>
        /// Q-Learning Function Takes graph as 2D array for adjency matrix. If there is a connection then you will put 1 otherwise 0
        /// Then you will set start and goal point. First you will train and create Q (quality) R(reward) matrices and then
        /// you will return passed nodes in path array from startpoint to goalpoint. 
        /// 
        /// You can use sample graphs but keypoint you should proof your paths and graphs.
        /// </summary>
        /// <param name="graph">2D adjency matrix</param>
        /// <param name="startPoint">index of start point</param>
        /// <param name="goalPoint">index of end point</param>
        /// <param name="path">include passed indexes from start to goal point</param>
        /// <returns>if success then return 0 otherwise returns -1</returns>
        public int TrainAndWalkQLearning(int[][] FT, int start, int goal, out int[] path)
        {
            path = new int[goal]; //you should set this parameters correctly

            //////////////////////////////////////
            //YOUR CODE HERE...
            //////////////////////////////////////
            Random rnd = new Random(1);
            int ns = 12;
           
            Console.WriteLine("Analyzing maze using Q-learning");

            double gamma = 0.5;
            double learnRate = 0.5;
            int maxEpochs = 1000;
           
            double[][] R;
            double[][] Q=new double[ns][];
             Q=  CreateQuality(ns);



            //The goal of Q-learning is to find the value of the Q matrix. Initially,
            //all Q values are set to 0.0 and the Q matrix is created like so
            double[][] CreateQuality(int n)
            {
                for (int i = 0; i < n; ++i)
                    Q[i] = new double[n];
                return Q;
            }



            //The reward matrix is defined by
            //In this example, moving to goal-cell 11 gives a reward of 10.0,
            //but any other move gives a negative reward of -0.1.
            R = new double[ns][];
            for (int i = 0; i < ns; ++i) R[i] = new double[ns];
            R[0][1] = R[0][4] = R[1][0] = R[1][5] = R[2][3] = -0.1;
            R[2][6] = R[3][2] = R[3][7] = R[4][0] = R[4][8] = -0.1;
            R[5][1] = R[5][6] = R[5][9] = R[6][2] = R[6][5] = -0.1;
            R[6][7] = R[7][3] = R[7][6] = R[7][11] = R[8][4] = -0.1;
            R[8][9] = R[9][5] = R[9][8] = R[9][10] = R[10][9] = -0.1;
            R[7][11] = 10.0;  // Goal




            for (int epoch = 0; epoch < maxEpochs; ++epoch)
            {
                int currState = rnd.Next(0, R.Length);

                while (true)
                {
                    int nextState = GetRandNextState(currState, FT);
                    System.Collections.Generic.List<int> possNextNextStates = GetPossNextStates(nextState, FT);
                    double maxQ = double.MinValue;
                    for (int j = 0; j < possNextNextStates.Count; ++j)
                    {
                        int nns = possNextNextStates[j];  // short alias
                        double q = Q[nextState][nns];
                        if (q > maxQ) maxQ = q;
                    }

                    Q[currState][nextState] =
    ((1 - learnRate) * Q[currState][nextState]) +
    (learnRate * (R[currState][nextState] + (gamma * maxQ)));
                    currState = nextState;
                    if (currState == goal) break;
                } // while
            } // for





            //As you’ll see shortly,
            //the Q-learning algorithm needs to know what states the system can transition to,
            //given a current state.
            System.Collections.Generic.List<int> GetPossNextStates(int s, int[][] FT1)
            {
                System.Collections.Generic.List<int> result = new System.Collections.Generic.List<int>();
                for (int j = 0; j < FT1.Length; ++j)
                    if (FT1[s][j] == 1) result.Add(j);
                return result;
            }



            //The Q-learning algorithm sometimes goes from the current state to a random next state.
            //That functionality is defined by method GetRandNextState:
             int GetRandNextState(int s, int[][] FT2)
            {

                List<int> possNextStates = GetPossNextStates(s, FT2);
                int ct = possNextStates.Count;
                int idx = rnd.Next(0, ct);
                return possNextStates[idx];
            }





            //After the quality matrix has been computed,
            //it can be used to find an optimal path from any starting state to the goal state.
            int k = 0;
            int curr = start; int next;
            path[k] = curr; k = k + 1;
            Console.Write(curr + "->");


                while (curr != goal)
                {
                    next = ArgMax(Q[curr]);
                    Console.Write(next + "->");
                    path[k] = next; k = k + 1;
                curr = next;


                }
                Console.WriteLine("done");

            




            //The method uses helper ArgMax to find the best next state
           int ArgMax(double[] vector)
        {

            double maxVal = vector[0]; int idx = 0;
            for (int i = 0; i < vector.Length; ++i)
            {
                if (vector[i] > maxVal)
                {
                    maxVal = vector[i]; idx = i;
                }
            }
            return idx;

        }

    return 0;
        }

        #endregion

        #region Dijsktra
        /// <summary>
        /// This function takes adjency matrix with weight and returns distance and passed path nodes for selected start and goal point
        /// path array includes node numbers, adjency matrix is represent a weighted graph you can check sample graph.
        /// </summary>
        /// <param name="startPoint">index of start point</param>
        /// <param name="goalPoint">index of end point</param>
        /// <param name="adjacencyMatrix">2D adjency and weight array</param>
        /// <param name="distance">total distance from startpoint to goal point</param>
        /// <param name="path">include passed indexes from start to goal point</param>
        /// <returns>if success then return 0 otherwise returns -1</returns>
        /// 


        public int WalkDijsktra(int src, int V, int[,] graph, out int distance, out int[] dist)
        {
            
            distance = -1; 
                dist = new int[V];
            //////////////////////////////////////
            //YOUR CODE HERE...
            //////////////////////////////////////



            // sptSet[i] will true if vertex
            // i is included in shortest path
            // tree or shortest distance from
            // src to i is finalized
            bool[] sptSet = new bool[V];

            // Initialize all distances as
            // INFINITE and stpSet[] as false
            for (int i = 0; i < V; i++)
            {
                dist[i] = int.MaxValue;
                sptSet[i] = false;
            }

            // Distance of source vertex
            // from itself is always 0
            dist[src] = 0;

            // Find shortest path for all vertices
            for (int count = 0; count < V - 1; count++)
            {
                // Pick the minimum distance vertex
                // from the set of vertices not yet
                // processed. u is always equal to
                // src in first iteration.
                int u = minDistance(dist, sptSet);

                // Mark the picked vertex as processed
                sptSet[u] = true;

                // Update dist value of the adjacent
                // vertices of the picked vertex.
                for (int v = 0; v < V; v++)

                    // Update dist[v] only if is not in
                    // sptSet, there is an edge from u
                    // to v, and total weight of path
                    // from src to v through u is smaller
                    // than current value of dist[v]
                    if (!sptSet[v] && graph[u, v] != 0 && dist[u] != int.MaxValue && dist[u] + graph[u, v] < dist[v])
                        dist[v] = dist[u] + graph[u, v];
                         
               
            }

            int minDistance(int[] dist1,
                     bool[] sptSet1)
            {
                // Initialize min value
                int min = int.MaxValue, min_index = -1;

                for (int v = 0; v < V; v++)
                    if (sptSet1[v] == false && dist1[v] <= min)
                    {
                        min = dist1[v];
                        min_index = v;
                    }

                return min_index;
            }


            for (int i = 0; i < V; i++)
            {
                Console.Write(i + " \t\t " + dist[i] + "\n");

                

            }
            return 0;
        }






















        #endregion

        #region Musicbox : 0-1 Knapsack Problem



        //////////////////////////////////////
        //YOUR CODE HERE...
        //////////////////////////////////////

        public int MusicBox(double estimatedDuration, double[] musicList, out double[] selectedMusicIndexes)
        {

            int n = musicList.Length;
            selectedMusicIndexes = new double[n];



            //value = in weight
            double[] val = new double[musicList.Length];
            Array.Copy(musicList, val, n);

           


            int i, w;
            int[,] K = new int[n + 1, (int)(estimatedDuration + 1)];

            // Build table K[][] in bottom up manner
            for (i = 0; i <= n; i++)
            {
                for (w = 0; w <= estimatedDuration; w++)
                {
                    if (i == 0 || w == 0)
                        K[i, w] = 0;
                    else if (musicList[i - 1] <= w)
                        K[i, w] = (int)Math.Max(val[i - 1] +
                                K[i - 1, w - (int)musicList[i - 1]], K[i - 1, w]);
                    else
                        K[i, w] = K[i - 1, w];
                }
            }

            // stores the result of Knapsack
            double res = K[n, (int)estimatedDuration];
            Console.WriteLine(res);
            int k = 0;
            w = (int)estimatedDuration;
            for (i = n; i > 0 && res > 0; i--)
            {

                // either the result comes from the top
                // (K[i-1][w]) or from (val[i-1] + K[i-1]
                // [w-wt[i-1]]) as in Knapsack table. If
                // it comes from the latter one/ it means
                // the item is included.
                if (res == K[i - 1, w])
                    continue;
                else
                {

                    // This item is included.
                   
                  selectedMusicIndexes[k] = musicList[i - 1] ;
                    k = k + 1;

                      // Since this weight is included its
                      // value is deducted
                    res = res - val[i - 1];
                    w = w - (int)musicList[i - 1];
                }
            }


            return 0;
        }
        #endregion

        #region FileEncryption
        /// <summary>
        /// Read image or any binary file from sourcepath
        /// Calculate sha256 hash of data
        /// use your key and AES CBC zero padding encryption function above
        /// do not forget to convert hexadecimal key to binary byte array
        /// calculate padding and apped to defined format below
        /// set 4 byte length information for data and hash length to trim padding from decryption buffer
        /// write file to destination path
        /// FORMAT : [4 byte length]+[32 byte length SHA256]+[n bytes length file data]+[padding if requried]
        /// PaddingMode.Zeros will be used and padding will be automatically calculated added to your buffer
        /// </summary>
        /// <param name="sourcePath"></param>
        /// <param name="destinationPath"></param>
        /// <param name="key"></param>
        /// <returns>if success then return 0 otherwise returns -1</returns>
        public int EncryptFile(string sourcePath, string destinationPath, string key)
        {
            //////////////////////////////////////
            //YOUR CODE HERE...
            //////////////////////////////////////

            return 0;
        }
        /// <summary>
        /// Read file from source path
        /// AES CBC PaddingZeros will be selected but last zero buffers won't be cleaned you should  clean them
        /// Decrypt File
        /// FORMAT : [4 byte length]+[32 byte length SHA256]+[n bytes length file data]+[padding if requried]
        /// Read length information and trim padding
        /// Extract SHA256 Hash and recalculate file data SHA256 hash
        /// Compare hash values if matched then write file data to destination path and return current and expected hash values as output
        /// Do not forget to convert binary hash values to hexadecimal string 
        /// Actual and Expected SHA256 hash will be calculated and compared if not matched then return false and assign
        /// current (out string currentFileHash) and expected file hash (out string expectedFileHash) to output parameters that we defined here.
        /// </summary>
        /// <param name="sourcePath">Encrypted file path</param>
        /// <param name="destinationPath">Decrypted file path</param>
        /// <param name="key">16 bytes key data hexadecimal string</param>
        /// <param name="currentFileHash">32 bytes hash data hexadecimal string calculated from file data </param>
        /// <param name="expectedFileHash">32 bytes hash data hexadecimal string read from file data</param>
        /// <returns>if success then return 0 otherwise returns -1</returns>
        public int DecryptFile(string sourcePath, string destinationPath, string key, out string currentFileHash, out string expectedFileHash)
        {
            //AES CBC PaddingZeros will be selected but last zero buffers won't be cleaned you should  clean them
            //Image file will be decrypted here..

            currentFileHash = null;
            expectedFileHash = null;

            //////////////////////////////////////
            //YOUR CODE HERE...
            //////////////////////////////////////

            return 0;
        }
        #endregion

        //integer counter this can be unix epoc
        //I defined a 20 byte key
        //counter converted to byte array counter=byte []data
        //Converted key to byte with byte[] ToBytes(string key1)
        //Generated one-time password with string ComputeTotp()

        #region OTP
        /// <summary>
        /// Calculate Counterbased One-Time-Password in Numeric Format with
        /// H-MAC SHA-1 and return as integer
        /// </summary>
        /// <param name="counter">4 bytes integer counter this can be unix epoch (https://www.epochconverter.com/hex)</param>
        /// <param name="key">20 bytes key for SHA-1 OTP in hexadecimal format</param>
        /// <returns>numeric OTP</returns>
        public int calculateOTP(int counter, string key , out string result)
        {
            //////////////////////////////////////
            //YOUR CODE HERE...
            //////////////////////////////////////
            //

            //counter converted to byte array counter=byte []data
            byte[] data = BitConverter.GetBytes(counter);
            if (BitConverter.IsLittleEndian)
                Array.Reverse(data);



            const int totpSize = 6;

            var bytes = ToBytes(key);

              byte[]  key_ = bytes;

            result =  ComputeTotp();



            //Generated one-time password with string ComputeTotp()
            string ComputeTotp()
            {
               
                var hmac = new HMACSHA1();
                hmac.Key = key_;
                var hmacComputedHash = hmac.ComputeHash(data);

                int offset = hmacComputedHash[hmacComputedHash.Length - 1] & 0x0F;
                var otp = (hmacComputedHash[offset] & 0x7f) << 24
                       | (hmacComputedHash[offset + 1] & 0xff) << 16
                       | (hmacComputedHash[offset + 2] & 0xff) << 8
                       | (hmacComputedHash[offset + 3] & 0xff) % 1000000;

                var hash = Digits(otp, totpSize);
                
                return hash;
            }


              string Digits(long input, int digitCount)
            {
                var truncatedValue = ((int)input % (int)Math.Pow(10, digitCount));
                return truncatedValue.ToString().PadLeft(digitCount, '0');
            }




            //Converted key to byte with byte[] ToBytes(string key1)
            byte[] ToBytes(string key1)
            {
                if (string.IsNullOrEmpty(key1))
                {
                    throw new ArgumentNullException("input");
                }

                key1 = key1.TrimEnd('='); //remove padding characters
                int byteCount = key1.Length * 5 / 8; //this must be TRUNCATED
                byte[] returnArray = new byte[byteCount];

                byte curByte = 0, bitsRemaining = 8;
                int mask = 0, arrayIndex = 0;

                foreach (char c in key1)
                {
                    int cValue = CharToValue(c);

                    if (bitsRemaining > 5)
                    {
                        mask = cValue << (bitsRemaining - 5);
                        curByte = (byte)(curByte | mask);
                        bitsRemaining -= 5;
                    }
                    else
                    {
                        mask = cValue >> (5 - bitsRemaining);
                        curByte = (byte)(curByte | mask);
                        returnArray[arrayIndex++] = curByte;
                        curByte = (byte)(cValue << (3 + bitsRemaining));
                        bitsRemaining += 3;
                    }
                }

                //if we didn't end with a full byte
                if (arrayIndex != byteCount)
                {
                    returnArray[arrayIndex] = curByte;
                }
                Console.WriteLine(returnArray[1]);
                return returnArray;

            }

             string ToString(byte[] input)
            {
                if (input == null || input.Length == 0)
                {
                    throw new ArgumentNullException("input");
                }

                int charCount = (int)Math.Ceiling(input.Length / 5d) * 8;
                char[] returnArray = new char[charCount];

                byte nextChar = 0, bitsRemaining = 5;
                int arrayIndex = 0;

                foreach (byte b in input)
                {
                    nextChar = (byte)(nextChar | (b >> (8 - bitsRemaining)));
                    returnArray[arrayIndex++] = ValueToChar(nextChar);

                    if (bitsRemaining < 4)
                    {
                        nextChar = (byte)((b >> (3 - bitsRemaining)) & 31);
                        returnArray[arrayIndex++] = ValueToChar(nextChar);
                        bitsRemaining += 5;
                    }

                    bitsRemaining -= 3;
                    nextChar = (byte)((b << bitsRemaining) & 31);
                }

                //if we didn't end with a full char
                if (arrayIndex != charCount)
                {
                    returnArray[arrayIndex++] = ValueToChar(nextChar);
                    while (arrayIndex != charCount) returnArray[arrayIndex++] = '='; //padding
                }

                return new string(returnArray);
            }

            int CharToValue(char c)
            {
                int value = (int)c;

                //65-90 == uppercase letters
                if (value < 91 && value > 64)
                {
                    return value - 65;
                }
                //50-55 == numbers 2-7
                if (value < 56 && value > 49)
                {
                    return value - 24;
                }
                //97-122 == lowercase letters
                if (value < 123 && value > 96)
                {
                    return value - 97;
                }

                throw new ArgumentException("Character is not a Base32 character.", "c");
            }

          char ValueToChar(byte b)
            {
                if (b < 26)
                {
                    return (char)(b + 65);
                }

                if (b < 32)
                {
                    return (char)(b + 24);
                }

                throw new ArgumentException("Byte is not a value Base32 value.", "b");

            }
           
            return 0; 
            
        }
        #endregion






    }
}
