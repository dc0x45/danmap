import javax.swing.SwingUtilities;

public class danmap {
    private void init() {
        what.main(new String[0]);
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                try {
                    new danmap().init();
                } catch (Exception e) {
                    System.out.println(e);
                }
            }
        });
    }
}