module byte_rotation(input logic clk, reset_n, start,
							input logic [15:0] message_addr, size, output_addr,
							output logic done, mem_clk, mem_we,
							output logic [15:0] mem_addr,
							output logic [31:0] mem_write_data,
							input logic [31:0] mem_read_data);
							
	function logic [31:0] byte_rotate(input logic [31:0] value);
		byte_rotate = {value[23:16], value[15:8], value[7:0], value[31:24]};
	endfunction
	
	logic [15:0] count;
	logic [15:0] temp_write_addr;
	logic [15:0] temp_read_addr;
	
	//initiate states
	enum logic [2:0] {IDLE=3'b000, READ_1=3'b001, READ_2=3'b010, WRITE_1=3'b011, WRITE_2=3'b100} state;
	
	//assignments
	assign mem_clk = clk;
	assign done = (state === IDLE);
	
	always_ff@(posedge clk, negedge reset_n) begin
		if (!reset_n) begin
			state <= IDLE;
		end 
		else begin
			case (state)
				IDLE:
					if (start) begin
						count <= size; //size is # words to read from memory
						temp_read_addr <= message_addr;
						temp_write_addr <= output_addr;
						state <= READ_1;
					end
				READ_1: begin
					mem_addr <= temp_read_addr;
					mem_we <= 0; //read from mem_addr to mem_read_data
					temp_read_addr <= temp_read_addr + 1;
					state <= READ_2;
				end
				READ_2: begin
					mem_addr <= temp_read_addr;
					mem_we <= 0; //read from mem_addr to mem_read_data
					temp_read_addr <= temp_read_addr + 1;
					state <= WRITE_1;
				end
				WRITE_1: //mem_read_data updated from READ_1 this cycle
					if (count > 0) begin
						mem_addr <= temp_write_addr;
						mem_write_data <= byte_rotate(mem_read_data); //use function so rotated instantly
						mem_we <= 1; //write from mem_write_data to mem_addr
						temp_write_addr <= temp_write_addr + 1;
						count <= count - 1;
						state <= WRITE_2;
					end 
					else begin
						state <= IDLE;
					end
				WRITE_2: //mem_read_data updated from READ_2 this cycle
					if (count > 0) begin
						mem_addr <= temp_write_addr;
						mem_write_data <= byte_rotate(mem_read_data); //use function so rotated instantly
						mem_we <= 1; //write from mem_write_data to mem_addr
						temp_write_addr <= temp_write_addr + 1;
						count <= count - 1;
						state <= READ_1;
					end 
					else begin
						state <= IDLE;
					end
			endcase
		end
	end
endmodule	
				