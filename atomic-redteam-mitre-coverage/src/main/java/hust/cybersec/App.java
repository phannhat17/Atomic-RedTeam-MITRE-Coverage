package hust.cybersec;

import hust.cybersec.data.model.AtomicRedTeam;
import hust.cybersec.data.model.MitreAttackFramework;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.InputMismatchException;
import java.util.Scanner;

public class App {
    static MitreAttackFramework mitre = new MitreAttackFramework();
    static AtomicRedTeam atomic = new AtomicRedTeam();

    public static void main(String[] args) throws URISyntaxException, IOException {
        Scanner scanner = new Scanner(System.in);

        System.out.println("Welcome to the Atomic RedTeam - MITRE Coverage app!");

        while (true) {
            System.out.println("Choose an option:");
            System.out.println("1. Download Data");
            System.out.println("2. Export Excel");
            System.out.println("3. View Analysis Chart");
            System.out.println("0. Exit");

            try {
                int option = scanner.nextInt();
                scanner.nextLine(); // Consume the newline character

                switch (option) {
                    case 1:
                        mitre.downloadData();
                        atomic.downloadData();
                        break;
                    case 2:
                        atomic.exportExcel();
                        break;
                    case 3:
                        atomic.analyseCoverage();
                        break;
                    case 0:
                        System.out.println("Exiting...");
                        return;
                    default:
                        System.out.println("Invalid option. Please try again.");
                        continue;
                }
            } catch (InputMismatchException e) {
                System.out.println("Invalid input. Please enter a number.");
                scanner.nextLine(); // Consume the invalid input
                continue;
            }

            System.out.println("Do you want to perform another action? (Enter 'y' to continue or any other key to exit)");
            String continueOption = scanner.nextLine();

            if (!continueOption.equalsIgnoreCase("y")) {
                System.out.println("Exiting...");
                break;
            }
        }
    }
}
