 import javax.swing.JFrame;
 import javax.swing.JPanel;
 import javax.swing.JComboBox;
 import javax.swing.JButton;
 import javax.swing.JLabel;
 import javax.swing.JList;
 import java.awt.*;
 import java.awt.event.ActionListener;
 import java.awt.event.ActionEvent;

public class Desktop_GUI extends JFrame{


    public static void main(String[] args){
        Desktop_GUI desk_gui = new Desktop_GUI("test", new Dimension(800, 600));
    }

    private Desktop_GUI(String title, Dimension size) {
        JFrame frame = mainFrame(title, size);
    }

    private JFrame mainFrame(String title, Dimension size){
        JFrame frame = new JFrame(title);

        frame.setPreferredSize(size);
        frame.setSize(800, 600);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setVisible(true);
        frame.setBackground(Color.darkGray);
        frame.getContentPane().setLayout(new GridBagLayout());
        //need to alter gridbag before
//      frame.getContentPane().add(mainPanel(new Dimension(600, 400)), new Grid);

        frame.add(chatter(new Dimension(800, 600)));


        frame.pack();

        return frame;
    }



    private JPanel chatter(Dimension sizeScale){

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(15,15,15,15);

        JPanel chatroom = new JPanel(new GridBagLayout());

        chatroom.setPreferredSize(sizeScale);
        chatroom.setLocation(300, 300);

        JTextArea textArea = new JTextArea("text area");
        JTextField textField = new JTextField("text field");

        chatroom.add(textArea, gbc);
        chatroom.add(textField, gbc);

        
        return chatroom;
    }


    private JPanel mainPanel(Dimension frame){
        JPanel mainPanel = new JPanel(new GridBagLayout());
        mainPanel.add(chatter(frame));

        return mainPanel;
    }
}


