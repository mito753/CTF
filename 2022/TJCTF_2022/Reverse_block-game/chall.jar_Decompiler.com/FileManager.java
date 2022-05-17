import java.io.FileOutputStream;

public class FileManager {
   public static void saveData(byte[] var0) {
      try {
         FileOutputStream var1 = new FileOutputStream("data.dat");
         var1.write(var0);
         var1.close();
      } catch (Exception var2) {
         var2.printStackTrace();
      }

   }
}
