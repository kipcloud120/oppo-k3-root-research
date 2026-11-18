import android.os.IBinder;
import android.os.Parcel;
import android.os.ServiceManager;

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

    public static void main(String[] args) {
        try {
            IBinder b = ServiceManager.getService("wifi");
            System.out.println("BINDER=" + b);
            if (b == null) return;
            int code = args.length > 0 ? Integer.parseInt(args[0]) : 10069;
            String token = args.length > 1 ? args[1] : "android.net.wifi.IOplusWifiManager";
            String arg = args.length > 2 ? args[2] : null;
            System.out.println("CODE=" + code + " TOKEN=" + token + " ARG=" + arg);
            Parcel d = Parcel.obtain();
            Parcel r = Parcel.obtain();
            d.writeInterfaceToken(token);
            if (arg != null) d.writeString(arg);
            boolean ok = b.transact(code, d, r, 0);
            System.out.println("TRANSACT=" + ok);
            r.setDataPosition(0);
            hex(r, "REPLY");
            r.readException();
            System.out.println("INT=" + r.readInt());
        } catch (Throwable t) {
            System.out.println("EX " + t);
        }
    }
}
