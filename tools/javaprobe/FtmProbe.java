import android.os.IBinder;
import android.os.Parcel;
import android.os.ServiceManager;
import java.io.File;
import java.io.FileInputStream;
import java.io.ByteArrayOutputStream;

public class FtmProbe {
    static void hex(Parcel p, String tag) {
        try {
            int n = p.dataSize();
            byte[] b = p.marshall();
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < Math.min(n, 80); i++) sb.append(String.format("%02x", b[i]));
            System.out.println(tag + " size=" + n + " hex=" + sb);
        } catch (Throwable t) {
            System.out.println(tag + " dump-ex " + t);
        }
    }

    /** 打印字符串的码点序列，用于确认换行等控制字符是否原样保留。 */
    static String desc(String s) {
        StringBuilder sb = new StringBuilder();
        sb.append("len=").append(s.length()).append(" cp=");
        for (int i = 0; i < Math.min(s.length(), 64); i++) {
            char c = s.charAt(i);
            if (c < 0x20 || c > 0x7e) sb.append(String.format("\\x%02x", (int) c));
            else sb.append(c);
        }
        return sb.toString();
    }

    static byte[] readAll(String path) throws Exception {
        FileInputStream in = new FileInputStream(new File(path));
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[4096];
        int n;
        while ((n = in.read(buf)) > 0) bos.write(buf, 0, n);
        in.close();
        return bos.toByteArray();
    }

    public static void main(String[] args) {
        try {
            IBinder b = ServiceManager.getService("wifi");
            System.out.println("BINDER=" + b);
            if (b == null) return;
            int code = args.length > 0 ? Integer.parseInt(args[0]) : 10069;
            String token = args.length > 1 ? args[1] : "android.net.wifi.IOplusWifiManager";
            String arg = args.length > 2 ? args[2] : null;
            // 支持 @file：从文件读取原始字节构造字符串，避免 adb shell 的引号/转义干扰
            if (arg != null && arg.startsWith("@") && args.length > 3) {
                String path = args[3];
                byte[] raw = readAll(path);
                System.out.println("PAYLOAD_FILE=" + path + " bytes=" + raw.length);
                arg = new String(raw, "UTF-8");
            }
            System.out.println("CODE=" + code + " TOKEN=" + token);
            if (arg != null) System.out.println("ARG " + desc(arg));
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            d.writeInterfaceToken(token);
            if (arg != null) d.writeString(arg);
            boolean ok = b.transact(code, d, r, 0);
            System.out.println("TRANSACT=" + ok);
            r.setDataPosition(0);
            hex(r, "REPLY");
            r.readException();
            // 不同事务返回类型不同：尽量按 boolean/int/string 依次尝试
            try {
                System.out.println("INT=" + r.readInt());
            } catch (Throwable t) {
                System.out.println("INT-EX " + t);
            }
        } catch (Throwable t) {
            System.out.println("EX " + t);
        }
    }
}
