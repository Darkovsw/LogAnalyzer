import java.io.File;
import java.io.FileNotFoundException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// regex na biblioteke
// \[(.*?)\]

//    regex na severity
//    \s([A-Z]+)\s+(?=\[)

//    regex na date i czas
//     (\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3})

//    Severity ranks lowest-highest: https://stackoverflow.com/questions/7745885/log4j-logging-hierarchy-order
// 1.TRACE
// 2.DEBUG
// 3.INFO
// 4.WARN
// 5.ERROR
// 6.FATAL
// 7.ALL
// 8.OFF

// AUTHOR: Jan Trojanowski

public class LogAnalyzer {

    public static void main(String[] args) {
        String path = "D:\\logs";
        processLogs(path);
    }

    private static void processLogs(String path) {
        File dir = new File(path);

        if (!validateDirectory(dir)) {
            System.out.println("Wrong path to the logs directory.");
            return;
        }

        File[] files = getSortedFilesByLastModified(dir);

        for (File file : files) {
            processLogFile(file);
        }
    }

    private static boolean validateDirectory(File dir) {
        return dir.exists() && dir.isDirectory();
    }

    private static File[] getSortedFilesByLastModified(File dir) {
        File[] files = dir.listFiles();
        assert files != null;
        Arrays.sort(files, Comparator.comparingLong(File::lastModified).reversed());
        return files;
    }

    private static void processLogFile(File file) {
        Map<String, Integer> matchCounts = new HashMap<>();
        Map<String, Set<String>> uniqueAppearances = new HashMap<>();
        List<Date> dateList = new ArrayList<>();

        long start = System.currentTimeMillis();
        printFileDetails(file);

        try {
            Scanner read = new Scanner(file);
            while (read.hasNextLine()) {
                String line = read.nextLine();
                processLogLine(line, matchCounts, uniqueAppearances);
                processDate(line, dateList);
            }
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        displayMatchCounts(matchCounts);
        displayUniqueAppearances(uniqueAppearances);
        displayTimeDifference(dateList);

        long end = System.currentTimeMillis();
        long elapsedTime = (end - start);
        System.out.println("File " + file.getName() + " reading time: " + (elapsedTime / 1000.0) + " seconds.");

        System.out.println("\n");
    }

    private static void printFileDetails(File file) {
        long lastModifiedTimestamp = file.lastModified();
        Date lastModifiedDate = new Date(lastModifiedTimestamp);

        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String formattedDate = dateFormat.format(lastModifiedDate);

        System.out.println("File: " + file.getName() + ", Last modified time: " + formattedDate);
    }

    private static void processLogLine(String data, Map<String, Integer> matchCounts, Map<String, Set<String>> uniqueAppearances) {
        String severityPattern = "\\s([A-Z]+)\\s+(?=\\[)";
        String libsPattern = "\\[(.*?)]";

        Pattern severityPatternCompiled = Pattern.compile(severityPattern);
        Pattern logsPatternCompiled = Pattern.compile(libsPattern);

        Matcher severityMatcher = severityPatternCompiled.matcher(data);
        if (severityMatcher.find()) {
            String severityGroup = severityMatcher.group().trim();
            matchCounts.put(severityGroup, matchCounts.getOrDefault(severityGroup, 0) + 1);
        }

        Matcher logsMatcher = logsPatternCompiled.matcher(data);
        while (logsMatcher.find()) {
            String logsGroup = logsMatcher.group(1);
            uniqueAppearances.computeIfAbsent(severityMatcher.group().trim(), key -> new HashSet<>()).add(logsGroup);
        }
    }

    private static void processDate(String data, List<Date> dateList) {
        String datePattern = "(\\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}:\\d{2},\\d{3})";

        Pattern datePatternCompiled = Pattern.compile(datePattern);
        Matcher dateMatcher = datePatternCompiled.matcher(data);

        while (dateMatcher.find()) {
            String dateString = dateMatcher.group(1);
            try {
                Date date = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS").parse(dateString);
                dateList.add(date);
            } catch (ParseException e) {
                e.printStackTrace();
            }
        }
    }

    private static void displayMatchCounts(Map<String, Integer> matchCounts) {
        System.out.println("####Grouped Severity Values:####");
        int sum = 0;
        int highlyRanked = 0;

        for (Map.Entry<String, Integer> entry : matchCounts.entrySet()) {
            sum += entry.getValue();
            if (Arrays.asList("ERROR", "FATAL", "ALL", "OFF").contains(entry.getKey())) {
                highlyRanked += 1;
            }
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }

        double percentage = (highlyRanked * 100.0) / sum;
        System.out.println("####ERROR and higher severities are: " + String.format("%.2f", percentage) + "% of all logs in this file.####");
    }

    private static void displayUniqueAppearances(Map<String, Set<String>> uniqueAppearances) {
        System.out.println("####Unique Libs For Each Log Severity Value:#####");
        for (Map.Entry<String, Set<String>> entry : uniqueAppearances.entrySet()) {
            System.out.println(entry.getKey() + ": " + entry.getValue());
        }
    }

    private static void displayTimeDifference(List<Date> dateList) {
        if (dateList.size() > 1) {
            Collections.sort(dateList);

            Date earliestDate = dateList.get(0);
            Date latestDate = dateList.get(dateList.size() - 1);

            long timeDifferenceInMillis = latestDate.getTime() - earliestDate.getTime();

            long daysDifference = timeDifferenceInMillis / (24 * 60 * 60 * 1000);
            long yearsDifference = daysDifference / 365;

            System.out.println("Time difference between the earliest and latest date: " + daysDifference + " days and " + yearsDifference + " years.");
        } else {
            System.out.println("Unable to calculate dates.");
        }
    }
}
