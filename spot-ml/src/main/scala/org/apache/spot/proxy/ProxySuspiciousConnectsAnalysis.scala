/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spot.proxy

import org.apache.log4j.Logger
import org.apache.spark.sql.functions._
import org.apache.spark.sql.types._
import org.apache.spark.sql.{DataFrame, SparkSession, Row, SaveMode}
import org.apache.spot.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.apache.spot.proxy.ProxySchema._
import org.apache.spot.utilities.data.validation.{InvalidDataHandler => dataValidation}

/**
  * Run suspicious connections analysis on proxy data.
  */
object ProxySuspiciousConnectsAnalysis {

  /**
    * Run suspicious connections analysis on proxy data.
    *
    * @param config       SuspicionConnectsConfig object, contains runtime parameters from CLI.
    * @param spark        SparkSession
    * @param logger       Logs execution progress, information and errors for user.
    */
  def run(config: SuspiciousConnectsConfig, spark: SparkSession, logger: Logger,
          inputProxyRecords: DataFrame) = {

    logger.info("Starting proxy suspicious connects analysis.")

    val cleanProxyRecords = filterAndSelectCleanProxyRecords(inputProxyRecords)

    val scoredProxyRecords = detectProxyAnomalies(cleanProxyRecords, config, spark, logger)

    ////////////////////////////////////////////////////////////////////////////////
    //Inserted code to save scores

    logger.info("Entering Gustavo planet")

    val newDF = scoredProxyRecords.select(Date, Time, ClientIP, Host, ReqMethod, Duration, ServerIP, SCBytes, CSBytes, Score, Word)
    val newWithIndexMapRDD = newDF.orderBy(Score).rdd.zipWithIndex()
    val newWithIndexRDD = newWithIndexMapRDD.map({case (row: Row, id: Long) => Row.fromSeq(row.toSeq ++ Array(id.toString))})


    val newDFStruct = new StructType(
      Array(
        StructField("date", StringType),
        StructField("time", StringType),
        StructField("clientIp",StringType),
        StructField("host",StringType),
        StructField("reqMethod",StringType),
        StructField("duration",IntegerType),
        StructField("serverIp",StringType),
        StructField("scbytes",IntegerType),
        StructField("csbytes",IntegerType),
        StructField("score",DoubleType),
        StructField("word",StringType),
        StructField("rank",StringType)))

    val indexDF = spark.createDataFrame(newWithIndexRDD, newDFStruct)

    logger.info(indexDF.count.toString)
    logger.info("persisting data with indexes")

    indexDF.createOrReplaceTempView("proxy_rank")
    spark.sql("DROP TABLE IF EXISTS proxy_spark21")
    spark.table("proxy_rank").write.saveAsTable("proxy_rank")

    //Inserted code to save scores
    /////////////////////////////////////////////////////////////////////////////////////


    // take the maxResults least probable events of probability below the threshold and sort

    val filteredProxyRecords = filterScoredProxyRecords(scoredProxyRecords, config.threshold)

    val orderedProxyRecords = filteredProxyRecords.orderBy(Score)

    val mostSuspiciousProxyRecords = if (config.maxResults > 0) orderedProxyRecords.limit(config.maxResults) else orderedProxyRecords

    val outputProxyRecords = mostSuspiciousProxyRecords.select(OutSchema: _*)

    logger.info("Proxy suspicious connects analysis completed")
    logger.info("Saving results to: " + config.hdfsScoredConnect)

    import spark.implicits._
    outputProxyRecords.map(_.mkString(config.outputDelimiter)).rdd.saveAsTextFile(config.hdfsScoredConnect)

    val invalidProxyRecords = filterAndSelectInvalidProxyRecords(inputProxyRecords)
    dataValidation.showAndSaveInvalidRecords(invalidProxyRecords, config.hdfsScoredConnect, logger)

    val corruptProxyRecords = filterAndSelectCorruptProxyRecords(scoredProxyRecords)
    dataValidation.showAndSaveCorruptRecords(corruptProxyRecords, config.hdfsScoredConnect, logger)
  }

  /**
    * Identify anomalous proxy log entries in in the provided data frame.
    *
    * @param data Data frame of proxy entries
    * @param config
    * @param spark
    * @param logger
    * @return
    */
  def detectProxyAnomalies(data: DataFrame,
                           config: SuspiciousConnectsConfig,
                           spark: SparkSession,
                           logger: Logger): DataFrame = {


    logger.info("Fitting probabilistic model to data")
    val model = ProxySuspiciousConnectsModel.trainNewModel(spark, logger, config, data)
    logger.info("Identifying outliers")

    model.score(spark, data)
  }

  /**
    *
    * @param inputProxyRecords raw proxy records.
    * @return
    */
  def filterAndSelectCleanProxyRecords(inputProxyRecords: DataFrame): DataFrame = {

    val cleanProxyRecordsFilter = inputProxyRecords(Date).isNotNull &&
      inputProxyRecords(Time).isNotNull &&
      inputProxyRecords(ClientIP).isNotNull &&
      inputProxyRecords(Host).isNotNull &&
      inputProxyRecords(FullURI).isNotNull

    inputProxyRecords
      .filter(cleanProxyRecordsFilter)
      .select(InSchema: _*)
      .na.fill(DefaultUserAgent, Seq(UserAgent))
      .na.fill(DefaultResponseContentType, Seq(ResponseContentType))
  }

  /**
    *
    * @param inputProxyRecords raw proxy records.
    * @return
    */
  def filterAndSelectInvalidProxyRecords(inputProxyRecords: DataFrame): DataFrame = {

    val invalidProxyRecordsFilter = inputProxyRecords(Date).isNull ||
      inputProxyRecords(Time).isNull ||
      inputProxyRecords(ClientIP).isNull ||
      inputProxyRecords(Host).isNull ||
      inputProxyRecords(FullURI).isNull

    inputProxyRecords
      .filter(invalidProxyRecordsFilter)
      .select(InSchema: _*)
  }

  /**
    *
    * @param scoredProxyRecords scored proxy records.
    * @param threshold          score tolerance.
    * @return
    */
  def filterScoredProxyRecords(scoredProxyRecords: DataFrame, threshold: Double): DataFrame = {

    val filteredProxyRecordsFilter = scoredProxyRecords(Score).leq(threshold) &&
      scoredProxyRecords(Score).gt(dataValidation.ScoreError)

    scoredProxyRecords.filter(filteredProxyRecordsFilter)
  }

  /**
    *
    * @param scoredProxyRecords scored proxy records.
    * @return
    */
  def filterAndSelectCorruptProxyRecords(scoredProxyRecords: DataFrame): DataFrame = {

    val corruptProxyRecordsFilter = scoredProxyRecords(Score).equalTo(dataValidation.ScoreError)

    scoredProxyRecords
      .filter(corruptProxyRecordsFilter)
      .select(OutSchema: _*)
  }

  val DefaultUserAgent = "-"
  val DefaultResponseContentType = "-"

  val InSchema = StructType(
    List(DateField,
      TimeField,
      ClientIPField,
      HostField,
      ReqMethodField,
      UserAgentField,
      ResponseContentTypeField,
      DurationField,
      UserNameField,
      WebCatField,
      RefererField,
      RespCodeField,
      URIPortField,
      URIPathField,
      URIQueryField,
      ServerIPField,
      SCBytesField,
      CSBytesField,
      FullURIField)).fieldNames.map(col)

  val OutSchema = StructType(
    List(DateField,
      TimeField,
      ClientIPField,
      HostField,
      ReqMethodField,
      UserAgentField,
      ResponseContentTypeField,
      DurationField,
      UserNameField,
      WebCatField,
      RefererField,
      RespCodeField,
      URIPortField,
      URIPathField,
      URIQueryField,
      ServerIPField,
      SCBytesField,
      CSBytesField,
      FullURIField,
      WordField,
      ScoreField)).fieldNames.map(col)
}