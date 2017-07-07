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
import org.apache.spot.SuspiciousConnects.SuspiciousConnectsAnalysisResults
import org.apache.spot.SuspiciousConnectsArgumentParser.SuspiciousConnectsConfig
import org.apache.spot.proxy.ProxySchema._
import org.apache.spot.utilities.data.validation.{InvalidDataHandler => dataValidation}

/**
  * Run suspicious connections analysis on proxy data.
  */
object ProxySuspiciousConnectsAnalysis {

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

  /**
    * Run suspicious connections analysis on proxy data.
    *
    * @param config       SuspicionConnectsConfig object, contains runtime parameters from CLI.
    * @param sparkSession Spark Session
    * @param logger       Logs execution progress, information and errors for user.
    */
  def run(config: SuspiciousConnectsConfig, sparkSession: SparkSession, logger: Logger,
          inputProxyRecords: DataFrame): SuspiciousConnectsAnalysisResults = {

    logger.info("Starting proxy suspicious connects analysis.")

    val proxyRecords = filterRecords(inputProxyRecords)
      .select(InSchema: _*)
      .na.fill(DefaultUserAgent, Seq(UserAgent))
      .na.fill(DefaultResponseContentType, Seq(ResponseContentType))

    logger.info("Fitting probabilistic model to data")
    val model = ProxySuspiciousConnectsModel.trainModel(sparkSession, logger, config, proxyRecords)

    logger.info("Identifying outliers")
    val scoredProxyRecords = model.score(sparkSession, proxyRecords, config.precisionUtility)

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

    val indexDF = sparkSession.createDataFrame(newWithIndexRDD, newDFStruct)

    logger.info(indexDF.count.toString)
    logger.info("persisting data with ranks")
    //indexDF.createOrReplaceTempView("zips_table")
    //sparkSession.sql("DROP TABLE IF EXISTS zips_hive_table")
    //save as a hive table
    //sparkSession.table("zips_table").write.mode(SaveMode.Overwrite).saveAsTable("zips_hive_table")

    indexDF.write.mode(SaveMode.Overwrite).saveAsTable("`proxy_rank`")
    //Inserted code to save scores
    /////////////////////////////////////////////////////////////////////////////////////

    // take the maxResults least probable events of probability below the threshold and sort

    val filteredScored = filterScoredRecords(scoredProxyRecords, config.threshold)

    val orderedProxyRecords = filteredScored.orderBy(Score)

    val mostSuspiciousProxyRecords =
      if (config.maxResults > 0) orderedProxyRecords.limit(config.maxResults)
      else orderedProxyRecords

    val outputProxyRecords = mostSuspiciousProxyRecords.select(OutSchema: _*)

    val invalidProxyRecords = filterInvalidRecords(inputProxyRecords).select(InSchema: _*)

    SuspiciousConnectsAnalysisResults(outputProxyRecords, invalidProxyRecords)

  }

  /**
    *
    * @param inputProxyRecords raw proxy records.
    * @return
    */
  def filterRecords(inputProxyRecords: DataFrame): DataFrame = {

    val cleanProxyRecordsFilter = inputProxyRecords(Date).isNotNull &&
      inputProxyRecords(Time).isNotNull &&
      inputProxyRecords(ClientIP).isNotNull &&
      inputProxyRecords(Host).isNotNull &&
      inputProxyRecords(FullURI).isNotNull

    inputProxyRecords
      .filter(cleanProxyRecordsFilter)
  }

  /**
    *
    * @param inputProxyRecords raw proxy records.
    * @return
    */
  def filterInvalidRecords(inputProxyRecords: DataFrame): DataFrame = {

    val invalidProxyRecordsFilter = inputProxyRecords(Date).isNull ||
      inputProxyRecords(Time).isNull ||
      inputProxyRecords(ClientIP).isNull ||
      inputProxyRecords(Host).isNull ||
      inputProxyRecords(FullURI).isNull

    inputProxyRecords
      .filter(invalidProxyRecordsFilter)
  }

  /**
    *
    * @param scoredProxyRecords scored proxy records.
    * @param threshold          score tolerance.
    * @return
    */
  def filterScoredRecords(scoredProxyRecords: DataFrame, threshold: Double): DataFrame = {

    val filteredProxyRecordsFilter = scoredProxyRecords(Score).leq(threshold) &&
      scoredProxyRecords(Score).gt(dataValidation.ScoreError)

    scoredProxyRecords.filter(filteredProxyRecordsFilter)
  }

}