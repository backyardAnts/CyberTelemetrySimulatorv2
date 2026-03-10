namespace CyberTelemetrySimulator.Utils;

public static class RandomDistributions
{
    public static double SampleNormal(Random random, double mean = 0, double stdDev = 1)
    {
        var u1 = 1.0 - random.NextDouble();
        var u2 = 1.0 - random.NextDouble();
        var randStdNormal = Math.Sqrt(-2.0 * Math.Log(u1)) * Math.Cos(2.0 * Math.PI * u2);
        return mean + stdDev * randStdNormal;
    }

    public static int SamplePoisson(Random random, double lambda)
    {
        if (lambda <= 0)
            return 0;

        if (lambda < 30)
        {
            var l = Math.Exp(-lambda);
            var k = 0;
            var p = 1.0;
            do
            {
                k++;
                p *= random.NextDouble();
            } while (p > l);
            return k - 1;
        }

        var normal = SampleNormal(random, lambda, Math.Sqrt(lambda));
        return (int)Math.Max(0, Math.Round(normal));
    }

    public static double SampleLogNormal(Random random, double mean, double sigma)
    {
        if (mean <= 0)
            return 0;

        var mu = Math.Log(mean) - 0.5 * sigma * sigma;
        return Math.Exp(mu + sigma * SampleNormal(random));
    }

    public static double SmoothAr1(Random random, double previous, double target, double alpha, double noiseStdDev)
    {
        var noise = SampleNormal(random, 0, noiseStdDev);
        return (alpha * previous) + ((1 - alpha) * target) + noise;
    }
}
