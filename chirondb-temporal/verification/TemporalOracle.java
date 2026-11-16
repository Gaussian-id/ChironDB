import java.util.Optional;
import org.apache.iotdb.db.queryengine.execution.aggregation.LastValueAccumulator;
import org.apache.tsfile.block.column.Column;
import org.apache.tsfile.enums.TSDataType;
import org.apache.tsfile.file.metadata.ChunkMetadata;
import org.apache.tsfile.file.metadata.statistics.DoubleStatistics;
import org.apache.tsfile.read.common.block.column.*;
import org.apache.tsfile.read.filter.factory.TimeFilterApi;

public class TemporalOracle extends LastValueAccumulator {
    TemporalOracle(TSDataType type) { super(type); }

    void partial(long t, int n) {
        Column time = new LongColumn(1, Optional.empty(), new long[]{t});
        Column val = seriesDataType == TSDataType.DOUBLE
            ? new DoubleColumn(1, Optional.empty(), new double[]{n})
            : new BooleanColumn(1, Optional.empty(), new boolean[]{n % 2 != 0});
        addIntermediate(new Column[]{val,time});
    }

    public static void main(String[] args) {
        for (long min : new long[]{-10,0,5,10}) {
            for (long max : new long[]{min,min+5,min+10}) {
                var stats = new DoubleStatistics();
                stats.update(min,1.0); stats.update(max,2.0);
                var metadata = new ChunkMetadata("sensor",TSDataType.DOUBLE,null,null,0,stats);
                for (long lo : new long[]{-11,0,5,10,20}) {
                    long hi=lo+5;
                    // TsFile between() includes its high endpoint.
                    var filter=TimeFilterApi.between(lo,hi-1);
                    String outcome=filter.canSkip(metadata)?"Skip":filter.allSatisfy(metadata)?"All":"Partial";
                    System.out.printf("range %d %d %d %d %s%n",lo,hi,min,max,outcome);
                }
            }
        }
        for (TSDataType type : new TSDataType[]{TSDataType.DOUBLE,TSDataType.BOOLEAN}) {
            for (long[] times : new long[][]{{},{-10,0,8},{8,0,-10},{1,7,-2,3},{Long.MIN_VALUE}}) {
                var acc=new TemporalOracle(type);
                var order=new StringBuilder();
                for(int i=0;i<times.length;i++){
                    if(i>0)order.append(",");
                    order.append(times[i]); acc.partial(times[i],i+1);
                }
                String value= !acc.initResult ? "empty" : type==TSDataType.DOUBLE
                    ? Long.toHexString(Double.doubleToRawLongBits(acc.lastValue.getDouble()))
                    : acc.lastValue.getBoolean()?"1":"0";
                System.out.printf("latest %s %s %d %s%n",type,order.length()==0?"empty":order,acc.maxTime,value);
            }
        }
    }
}
