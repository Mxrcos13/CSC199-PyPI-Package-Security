import luigi

class MyTask(luigi.Task):
    name = luigi.Parameter(default='world')

    def output(self):
        return luigi.LocalTarget(f'/tmp/hello_{self.name}.txt')

    def run(self):
        with self.output().open('w') as f:
            f.write(f'Hello, {self.name}!\n')

if __name__ == '__main__':
    luigi.build([MyTask()], local_scheduler=True)
