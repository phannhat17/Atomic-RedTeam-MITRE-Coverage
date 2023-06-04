import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.channels.Channels;
import java.nio.channels.ReadableByteChannel;

public class GetAtomic {

    public static void main(String[] args) {
        String downloadPath = "./atomic";
        File directory = new File(downloadPath);
        if (!directory.exists()) {
            directory.mkdirs();
        }
        String downloadUrl = "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/Indexes/index.yaml";
        
            try {
                downloadUsingNIO(downloadUrl, downloadPath + "/atomic-all.yaml");
            } catch (IOException e) {
                e.printStackTrace();
            }
        
    }

    private static void downloadUsingNIO(String urlStr, String file) throws IOException {
        long start = System.currentTimeMillis();
        URL url = new URL(urlStr);
        ReadableByteChannel rbc = Channels.newChannel(url.openStream());
        FileOutputStream fos = new FileOutputStream(file);
        fos.getChannel().transferFrom(rbc, 0, Long.MAX_VALUE);
        fos.close();
        rbc.close();
        long stop = System.currentTimeMillis();
        System.out.println("Run time: " + (stop - start));
    }

}
