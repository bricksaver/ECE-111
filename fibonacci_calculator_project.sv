module fibonacci_calculator_project (input logic clk, reset_n,
                             input logic [4:0] input_s,
                             input logic begin_fibo,
                            output logic [15:0] fibo_out,
                            output logic done);

  enum logic {IDLE=1'b0, COMPUTE=1'b1} state;

  logic  [4:0] count;
  logic [15:0] R0, R1;
  
  assign done = (count==1) ?1:0;
  assign fibo_out = R0;

  always_ff @(posedge clk, negedge reset_n)
  begin
    if (!reset_n) begin
      state <= IDLE;
      //done <= 0;
    end else
      case (state)
        IDLE:
          if (begin_fibo) begin
            count <= input_s;
            R0 <= 1;
            R1 <= 0;
            state <= COMPUTE;
          end
        COMPUTE:
          if (count > 1) begin
            count <= count - 1;
            R0 <= R0 + R1;
            R1 <= R0;
            $display("state = %s, count = %3d, R0 = %4d, R1 = %4d", state, count, R0, R1);
          end else begin
            state <= IDLE;
            //done <= 1;
            //fibo_out <= R0;
          end
      endcase
  end
  
  //assign done = (state==IDLE);
  //assign fibo_out = R0;
  
endmodule
						