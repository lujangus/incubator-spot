package org.apache.spot.netflow.model

import org.apache.spark.sql.types.StructType
import org.apache.spark.sql.{Row, SQLContext}
import org.apache.spot.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.apache.spot.netflow.FlowSchema._
import org.apache.spot.netflow.FlowSuspiciousConnectsAnalysis
import org.apache.spot.testutils.TestingSparkContextFlatSpec
import org.scalatest.Matchers

class FlowSuspiciousConnectsModelTest extends TestingSparkContextFlatSpec with Matchers {

  val testConfig = SuspiciousConnectsConfig(analysis = "flow",
    inputPath = "",
    feedbackFile = "",
    duplicationFactor = 1,
    topicCount = 20,
    hdfsScoredConnect = "",
    threshold = 1.0d,
    maxResults = 1000,
    outputDelimiter = "\t",
    ldaPRGSeed = None,
    ldaMaxiterations = 20,
    ldaAlpha = 1.02,
    ldaBeta = 1.001)

  "filterAndSelectCleanFlowRecords" should "return data set without garbage" in {

    val cleanedFlowRecords = FlowSuspiciousConnectsAnalysis.filterAndSelectCleanFlowRecords(testFlowRecords.inputFlowRecordsDF)

    cleanedFlowRecords.count should be(7)
    cleanedFlowRecords.schema.size should be(17)
  }

  def testFlowRecords = new {

    val inputFlowRecordsRDD = spark.sparkContext.parallelize(wrapRefArray(Array(
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 24, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 59, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 59, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l),
      Seq(null, 2016, 5, 5, 13, 54, 58, 0.972, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l, 12522l, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, null, "10.0.2.202", 1024, 80, "TCP", 39l, 12522l, 0l,
        0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", null, 1024, 80, "TCP", 39l, 12522l,
        0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", null, 80, "TCP", 39l,
        12522l, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, null, "TCP",
        39l, 12522l, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", null,
        12522l, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        null, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, null, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, null),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l))
      .map(row => Row.fromSeq(row))))

    val inputFlowRecordsSchema = StructType(
      Array(TimeReceivedField,
        YearField,
        MonthField,
        DayField,
        HourField,
        MinuteField,
        SecondField,
        DurationField,
        SourceIPField,
        DestinationIPField,
        SourcePortField,
        DestinationPortField,
        ProtocolField,
        IpktField,
        IbytField,
        OpktField,
        ObytField))

    val inputFlowRecordsDF = spark.createDataFrame(inputFlowRecordsRDD, inputFlowRecordsSchema)

    val scoredFlowRecordsRDD = spark.sparkContext.parallelize(wrapRefArray(Array(
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l, -1d),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l, 1d),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l, 0.0000005d),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l, 0.05d),
      Seq("2016-05-05 13:54:58", 2016, 5, 5, 13, 54, 58, 0.972d, "172.16.0.129", "10.0.2.202", 1024, 80, "TCP", 39l,
        12522l, 0l, 0l, 0.0001d))
      .map(row => Row.fromSeq(row))))

    val scoredFlowRecordsSchema = StructType(
      Array(TimeReceivedField,
        YearField,
        MonthField,
        DayField,
        HourField,
        MinuteField,
        SecondField,
        DurationField,
        SourceIPField,
        DestinationIPField,
        SourcePortField,
        DestinationPortField,
        ProtocolField,
        IpktField,
        IbytField,
        OpktField,
        ObytField,
        ScoreField))

    val scoredFlowRecordsDF = spark.createDataFrame(scoredFlowRecordsRDD, scoredFlowRecordsSchema)
  }
}
