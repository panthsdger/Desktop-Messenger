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
        //SETTING UP MAIN FRAME
        JFrame guiFrame = new JFrame();
        guiFrame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        guiFrame.setTitle("generic_gui");
        guiFrame.setSize(800,600);
        guiFrame.setLocationRelativeTo(null);
        guiFrame.setVisible(true);
        guiFrame.setExtendedState(JFrame.MAXIMIZED_BOTH);


        
        
        // FRAMES ANd BUTTONS FOR CLICKING
        JPanel buttonPanel = new JPanel();
        JButton resetButton = new JButton();
        JButton countButton = new JButton();
        countButton.setText(""+addup);
        resetButton.setText("Reset Count");
        buttonPanel.add(countButton);
        buttonPanel.add(resetButton);
        countButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addup++;
                countButton.setText(""+addup);
            }
        });
        resetButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                addup = 0;
                countButton.setText("0");
            }
        });
        guiFrame.add(buttonPanel);
    }
}
