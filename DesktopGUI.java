import javax.swing.JFrame;
import javax.swing.JPanel;
import javax.swing.JComboBox;
import javax.swing.JButton;
import javax.swing.JLabel;
import javax.swing.JList;
import java.awt.*;
import java.awt.event.ActionListener;
import java.awt.event.ActionEvent;

public class Desktop_GUI {
    int addup = 0;
    public static void main(String[] args){
        new Desktop_GUI();
    }

    public Desktop_GUI(){
        JFrame guiFrame = new JFrame();
        guiFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        guiFrame.setTitle("generic_gui");
        guiFrame.setSize(300,250);
        guiFrame.setLocationRelativeTo(null);
        guiFrame.setVisible(true);

        JPanel buttonPannel = new JPanel();
        buttonPannel.setMaximumSize(new Dimension(100, 100));
        JButton countButton = new JButton();
        countButton.setText(""+addup);
        buttonPannel.add(countButton);
        countButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addup++;
                countButton.setText(""+addup);
            }
        });
        guiFrame.add(buttonPannel);
    }
}
